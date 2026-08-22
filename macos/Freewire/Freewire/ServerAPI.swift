import Foundation

struct ServerConfig: Decodable {
    let publicKey: String
    let endpointHost: String
    let endpointPort: Int
    let tlsEndpointPort: Int
    let dnsTunnelPort: Int
    let icmpUDPPort: Int
    let capacityAvailable: Bool

    var endpoint: String { "\(endpointHost):\(endpointPort)" }

    enum CodingKeys: String, CodingKey {
        case publicKey = "public_key"
        case endpointHost = "endpoint_host"
        case endpointPort = "endpoint_port"
        case tlsEndpointPort = "tls_endpoint_port"
        case dnsTunnelPort = "dns_tunnel_port"
        case icmpUDPPort = "icmp_udp_port"
        case capacityAvailable = "capacity_available"
    }
}

struct RegisteredPeer: Decodable {
    let tunnelIP: String
    let tunnelIPv6: String
    let keepaliveInterval: Int
    let peerToken: String

    enum CodingKeys: String, CodingKey {
        case tunnelIP = "tunnel_ip"
        case tunnelIPv6 = "tunnel_ip_v6"
        case keepaliveInterval = "keepalive_interval"
        case peerToken = "peer_token"
    }
}

enum APIError: Error, LocalizedError {
    case badURL
    case httpError(Int)
    case serverUnreachable      // CONN-3
    case capacityFull           // CONN-4 (503 on peer registration)
    case serverAtCapacity       // CONN-4 (capacity_available=false in config)
    case decodeFailed(Error)
    case noServerPin
    case serverKeyMismatch
    case tokenRejected

    var errorDescription: String? {
        switch self {
        case .badURL:              return "Invalid server URL."
        case .httpError(let c):    return "Server returned \(c)."
        // Exact copy from error-states-spec.md
        case .serverUnreachable:   return "Freewire's servers are unreachable right now. Try again in a moment."
        case .capacityFull,
             .serverAtCapacity:    return "Freewire's servers are at capacity. Try again in a few minutes."
        case .decodeFailed:        return "Unexpected server response."
        // Copy per error-states-spec.md, "Server identity (TRUST)":
        // TRUST-1, TRUST-2 and TRUST-3 respectively.
        case .noServerPin:
            return "Freewire does not have a trusted key for this server. Add the server's key before connecting."
        case .serverKeyMismatch:
            return "This server's identity does not match the one Freewire trusts. Connection refused."
        case .tokenRejected:
            return "Freewire could not verify this connection. Try again in a moment."
        }
    }
}

final class ServerAPI {
    let serverHost: String
    private let http: PinnedHTTPClient

    init(host: String = "127.0.0.1", port: UInt16 = 8080) {
        serverHost = host
        // HTTPS only, over a client that verifies certificates itself.
        //
        // This endpoint hands over the server's WireGuard public key, the trust
        // anchor for the whole tunnel; over plaintext anyone on the path could
        // substitute their own. URLSession cannot serve here because ATS
        // rejects a self-signed certificate before any pinning code runs, and
        // the only escape it offers disables ATS for the entire app.
        http = PinnedHTTPClient(
            host: host,
            port: port,
            // A self-signed certificate is acceptable exactly when the user has
            // pinned a key out of band, because the pin rather than the
            // certificate is what establishes trust. A real hostname gets the
            // system's normal chain validation.
            acceptAnyCertificate: ServerTrust.trustsSelfSignedCertificate
        )
    }

    func fetchConfig() async throws -> ServerConfig {
        let cfg: ServerConfig
        do {
            let resp = try await http.request(method: "GET", path: "/v1/server/config")
            guard (200..<300).contains(resp.status) else {
                throw APIError.httpError(resp.status)
            }
            cfg = try decode(ServerConfig.self, from: resp.body)
        } catch let e as PinnedHTTPClient.Failure {
            _ = e
            throw APIError.serverUnreachable
        }

        // The certificate proves we reached the host we asked for. It does not
        // prove the key that host returned is the one this client should use:
        // a single mis-issued certificate would be enough to swap it. The key
        // is therefore checked against a pin carried independently.
        guard ServerTrust.isPinned else {
            throw APIError.noServerPin
        }
        guard ServerTrust.accepts(key: cfg.publicKey, host: serverHost) else {
            throw APIError.serverKeyMismatch
        }
        return cfg
    }

    /// Registers a peer, spending a Privacy Pass token when one is available.
    ///
    /// The token is the only thing presented. Nothing identifying the device
    /// accompanies it: adding a device id or any other handle would let the
    /// server correlate this registration with the issuance that produced the
    /// token, which is exactly what blind signing prevents — and it would still
    /// work, so the loss would be silent.
    func registerPeer(publicKeyBase64: String, token: String? = nil) async throws -> RegisteredPeer {
        let clientVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
        let body = try JSONEncoder().encode([
            "public_key":     publicKeyBase64,
            "client_version": clientVersion,
        ])
        var headers = ["Content-Type": "application/json"]
        if let token {
            headers["Authorization"] = "PrivateToken token=\(token)"
        }

        do {
            let resp = try await http.request(
                method: "POST", path: "/v1/peers", body: body, headers: headers
            )
            if resp.status == 503 { throw APIError.capacityFull }
            // 402 is the spec's code for both token failures, deliberately not
            // 401 or 429: the client maps those to different retries.
            if resp.status == 402 { throw APIError.tokenRejected }
            guard (200..<300).contains(resp.status) else {
                throw APIError.httpError(resp.status)
            }
            return try decode(RegisteredPeer.self, from: resp.body)
        } catch let e as PinnedHTTPClient.Failure {
            _ = e
            throw APIError.serverUnreachable
        }
    }

    func removePeer(token: String) async throws {
        // Best-effort: a failure here must not surface on disconnect, and 404
        // means the peer already expired, which is the same outcome.
        _ = try? await http.request(method: "DELETE", path: "/v1/peers/\(token)")
    }

    /// Blocking peer removal for `applicationWillTerminate`, which cannot await.
    ///
    /// The request runs on a detached task and this waits on a semaphore, so the
    /// main thread is never the one performing the work — awaiting a main-actor
    /// method from a termination handler would deadlock.
    func removePeerBlocking(token: String, timeout: TimeInterval = 2) {
        let sema = DispatchSemaphore(value: 0)
        let client = http
        Task.detached {
            _ = try? await client.request(
                method: "DELETE", path: "/v1/peers/\(token)", timeout: timeout
            )
            sema.signal()
        }
        _ = sema.wait(timeout: .now() + timeout)
    }

    // MARK: - Helpers

    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw APIError.decodeFailed(error)
        }
    }
}
