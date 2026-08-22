import Foundation
import Network

/// A minimal HTTPS client that verifies certificates itself.
///
/// URLSession will not do for the control plane. App Transport Security rejects
/// a self-signed certificate *before* the authentication-challenge delegate is
/// consulted, so a pinning client never gets the chance to accept one — the
/// connection fails with -1200 while the pin sits there, present and correct.
/// The only way out with URLSession is `NSAllowsArbitraryLoads`, which disables
/// ATS for the whole app to solve a problem with one host.
///
/// `Network.framework` lets the app perform verification in its own code, which
/// is what a pinning client wants regardless: the pin becomes the entire
/// verification rather than an override bolted onto the system's. A server with
/// a real hostname and a CA-signed certificate still gets normal validation.
///
/// This speaks only enough HTTP/1.1 for the control plane: one request per
/// connection, `Content-Length` bodies, no chunked encoding, no redirects,
/// no keep-alive.
final class PinnedHTTPClient: @unchecked Sendable {

    enum Failure: Error, LocalizedError {
        case connectionFailed(String)
        case timedOut
        case malformedResponse

        var errorDescription: String? {
            switch self {
            case .connectionFailed(let m): return "Connection failed: \(m)"
            case .timedOut:                return "The server did not respond in time."
            case .malformedResponse:       return "The server sent a malformed response."
            }
        }
    }

    struct Response {
        let status: Int
        let body: Data
    }

    private let host: String
    private let port: UInt16
    /// When true, any certificate is accepted and trust rests entirely on the
    /// pinned WireGuard key checked after the response is parsed.
    private let acceptAnyCertificate: Bool

    init(host: String, port: UInt16, acceptAnyCertificate: Bool) {
        self.host = host
        self.port = port
        self.acceptAnyCertificate = acceptAnyCertificate
    }

    func request(
        method: String,
        path: String,
        body: Data? = nil,
        headers: [String: String] = [:],
        timeout: TimeInterval = 10
    ) async throws -> Response {
        let connection = NWConnection(
            host: NWEndpoint.Host(host),
            port: NWEndpoint.Port(integerLiteral: port),
            using: makeParameters()
        )

        return try await withCheckedThrowingContinuation { cont in
            let done = Once()
            let queue = DispatchQueue(label: "com.freewire.http")

            queue.asyncAfter(deadline: .now() + timeout) {
                done.run {
                    connection.cancel()
                    cont.resume(throwing: Failure.timedOut)
                }
            }

            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    self.send(method, path, body, headers, over: connection) { result in
                        done.run {
                            connection.cancel()
                            cont.resume(with: result)
                        }
                    }
                case .failed(let error):
                    done.run {
                        connection.cancel()
                        cont.resume(throwing: Failure.connectionFailed(error.localizedDescription))
                    }
                case .cancelled:
                    done.run { cont.resume(throwing: Failure.connectionFailed("cancelled")) }
                default:
                    break
                }
            }
            connection.start(queue: queue)
        }
    }

    // MARK: - TLS

    private func makeParameters() -> NWParameters {
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_tls_server_name(tls.securityProtocolOptions, host)

        if acceptAnyCertificate {
            // Trust comes from the pinned WireGuard key, checked once the
            // response is parsed. An attacker who intercepts this session still
            // has to return the pinned key, and if they do, the WireGuard
            // handshake fails because they do not hold the matching private
            // key — denial of service, not interception.
            sec_protocol_options_set_verify_block(
                tls.securityProtocolOptions,
                { _, _, complete in complete(true) },
                DispatchQueue(label: "com.freewire.tls.verify")
            )
        }
        // Otherwise no verify block is installed and the system performs its
        // normal chain validation, which is what a real hostname deserves.

        return NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
    }

    // MARK: - HTTP

    private func send(
        _ method: String,
        _ path: String,
        _ body: Data?,
        _ headers: [String: String],
        over connection: NWConnection,
        completion: @escaping (Result<Response, Error>) -> Void
    ) {
        var request = "\(method) \(path) HTTP/1.1\r\n"
        request += "Host: \(host):\(port)\r\n"
        request += "Connection: close\r\n"
        for (k, v) in headers {
            request += "\(k): \(v)\r\n"
        }
        request += "Content-Length: \(body?.count ?? 0)\r\n\r\n"

        var out = Data(request.utf8)
        if let body { out.append(body) }

        connection.send(content: out, completion: .contentProcessed { error in
            if let error {
                completion(.failure(Failure.connectionFailed(error.localizedDescription)))
                return
            }
            // Connection: close means the response ends at EOF, so the reply is
            // read until the peer closes rather than parsed incrementally.
            self.receiveAll(connection, into: Data(), completion: completion)
        })
    }

    private func receiveAll(
        _ connection: NWConnection,
        into accumulated: Data,
        completion: @escaping (Result<Response, Error>) -> Void
    ) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { chunk, _, isComplete, error in
            if let error {
                completion(.failure(Failure.connectionFailed(error.localizedDescription)))
                return
            }
            var data = accumulated
            if let chunk { data.append(chunk) }

            if isComplete {
                if let parsed = Self.parse(data) {
                    completion(.success(parsed))
                } else {
                    completion(.failure(Failure.malformedResponse))
                }
                return
            }
            self.receiveAll(connection, into: data, completion: completion)
        }
    }

    /// Splits a response into its status and body.
    static func parse(_ data: Data) -> Response? {
        guard let separator = data.range(of: Data("\r\n\r\n".utf8)) else { return nil }
        let head = data[..<separator.lowerBound]
        let body = data[separator.upperBound...]

        guard let headText = String(data: head, encoding: .utf8),
              let statusLine = headText.split(separator: "\r\n").first else { return nil }
        // "HTTP/1.1 200 OK"
        let fields = statusLine.split(separator: " ")
        guard fields.count >= 2, let status = Int(fields[1]) else { return nil }

        return Response(status: status, body: Data(body))
    }
}

/// Runs a block at most once, from any thread.
///
/// The connection's state handler and the timeout fire on different queues, and
/// resuming a CheckedContinuation twice is an unconditional fatalError.
private final class Once: @unchecked Sendable {
    private let lock = NSLock()
    private var fired = false

    func run(_ block: () -> Void) {
        lock.lock()
        if fired { lock.unlock(); return }
        fired = true
        lock.unlock()
        block()
    }
}
