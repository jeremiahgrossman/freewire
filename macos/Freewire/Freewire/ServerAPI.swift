import Foundation

struct ServerConfig: Decodable {
    let publicKey: String
    let endpointHost: String
    let endpointPort: Int
    let capacityAvailable: Bool

    var endpoint: String { "\(endpointHost):\(endpointPort)" }

    enum CodingKeys: String, CodingKey {
        case publicKey = "public_key"
        case endpointHost = "endpoint_host"
        case endpointPort = "endpoint_port"
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

    var errorDescription: String? {
        switch self {
        case .badURL:              return "Invalid server URL."
        case .httpError(let c):    return "Server returned \(c)."
        // Exact copy from error-states-spec.md
        case .serverUnreachable:   return "Freewire's servers are unreachable right now. Try again in a moment."
        case .capacityFull,
             .serverAtCapacity:    return "Freewire's servers are at capacity. Try again in a few minutes."
        case .decodeFailed:        return "Unexpected server response."
        }
    }
}

final class ServerAPI {
    let serverHost: String
    private let base: URL
    private let session: URLSession

    init(host: String = "127.0.0.1", port: Int = 8080) {
        serverHost = host
        base = URL(string: "http://\(host):\(port)/v1")!
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 10
        session = URLSession(configuration: config)
    }

    func fetchConfig() async throws -> ServerConfig {
        let url = base.appendingPathComponent("server/config")
        do {
            let (data, response) = try await session.data(from: url)
            try checkStatus(response, data)
            return try decode(ServerConfig.self, from: data)
        } catch is URLError {
            throw APIError.serverUnreachable
        }
    }

    func registerPeer(publicKeyBase64: String) async throws -> RegisteredPeer {
        let url = base.appendingPathComponent("peers")
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        let clientVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
        req.httpBody = try JSONEncoder().encode([
            "public_key":     publicKeyBase64,
            "client_version": clientVersion,
        ])
        do {
            let (data, response) = try await session.data(for: req)
            if let http = response as? HTTPURLResponse, http.statusCode == 503 {
                throw APIError.capacityFull
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
