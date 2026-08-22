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
        // Copy per error-states-spec.md, "Server identity (TRUST)".
        case .noServerPin:
            return "Freewire does not have a trusted key for this server. Add the server's key before connecting."
        case .serverKeyMismatch:
            return "This server's identity does not match the one Freewire trusts. Connection refused."
        case .tokenRejected:
            return "Freewire could not verify this connection. Try again in a moment."
        }
    }
}

/// Accepts a self-signed certificate only when the user has pinned a key.
///
/// A server on a bare IP cannot hold a CA-signed certificate, so requiring one
/// would make self-hosting impossible. The pin is what establishes trust in
/// that case, not the certificate: an attacker who intercepts the TLS session
/// still has to return the pinned public key, and if they do, the WireGuard
/// handshake that follows fails because they do not hold the matching private
/// key. The worst they achieve is denial of service, not interception.
///
/// With no user pin, this delegate does nothing and the system's normal
/// certificate validation applies.
private final class PinnedTrustDelegate: NSObject, URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust,
              let pinned = ServerTrust.userPinnedKey, !pinned.isEmpty
        else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        completionHandler(.useCredential, URLCredential(trust: trust))
    }
}

final class ServerAPI {
    let serverHost: String
    private let base: URL
    private let session: URLSession
    private let trustDelegate = PinnedTrustDelegate()

    init(host: String = "127.0.0.1", port: Int = 8080) {
        serverHost = host
        // HTTPS only. This endpoint hands over the server's WireGuard public
        // key, which is the trust anchor for the tunnel; over plaintext anyone
        // on the path could substitute their own and terminate the tunnel
        // themselves.
        base = URL(string: "https://\(host):\(port)/v1")!
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 10
        session = URLSession(configuration: config,
                             delegate: trustDelegate,
                             delegateQueue: nil)
    }

    func fetchConfig() async throws -> ServerConfig {
        let url = base.appendingPathComponent("server/config")
        let cfg: ServerConfig
        do {
            let (data, response) = try await session.data(from: url)
            try checkStatus(response, data)
            cfg = try decode(ServerConfig.self, from: data)
        } catch is URLError {
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
        let url = base.appendingPathComponent("peers")
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let token {
            req.setValue("PrivateToken token=\(token)", forHTTPHeaderField: "Authorization")
        }
        let clientVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
        req.httpBody = try JSONEncoder().encode([
            "public_key":     publicKeyBase64,
            "client_version": clientVersion,
        ])
        do {
            let (data, response) = try await session.data(for: req)
            if let http = response as? HTTPURLResponse {
                if http.statusCode == 503 { throw APIError.capacityFull }
                // 402 is the spec's code for both token failures, deliberately
                // not 401 or 429: the client maps those to different retries.
                if http.statusCode == 402 { throw APIError.tokenRejected }
            }
            try checkStatus(response, data)
            return try decode(RegisteredPeer.self, from: data)
        } catch is URLError {
            throw APIError.serverUnreachable
        }
    }

    func removePeer(token: String) async throws {
        let url = base.appendingPathComponent("peers/\(token)")
        var req = URLRequest(url: url)
        req.httpMethod = "DELETE"
        do {
            let (_, response) = try await session.data(for: req)
            // Per spec: 404 means peer already expired/evicted — safe to ignore.
            if let http = response as? HTTPURLResponse, http.statusCode == 404 { return }
            try checkStatus(response, nil)
        } catch is URLError {
            // Best-effort — don't surface a network error on disconnect.
        }
    }

    /// Blocking peer removal for `applicationWillTerminate`, which cannot await.
    /// URLSession delivers its completion on a background queue, so waiting here
    /// does not deadlock the main thread the way awaiting a main-actor method would.
    func removePeerBlocking(token: String, timeout: TimeInterval = 2) {
        let url = base.appendingPathComponent("peers/\(token)")
        var req = URLRequest(url: url)
        req.httpMethod = "DELETE"
        req.timeoutInterval = timeout

        let sema = DispatchSemaphore(value: 0)
        session.dataTask(with: req) { _, _, _ in sema.signal() }.resume()
        _ = sema.wait(timeout: .now() + timeout)
    }

    // MARK: - Helpers

    private func checkStatus(_ response: URLResponse, _ body: Data?) throws {
        guard let http = response as? HTTPURLResponse else { return }
        guard (200..<300).contains(http.statusCode) else {
            throw APIError.httpError(http.statusCode)
        }
    }

    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw APIError.decodeFailed(error)
        }
    }
}
