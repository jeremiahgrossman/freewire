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
        case malformedRequest
        case responseTooLarge

        var errorDescription: String? {
            switch self {
            case .connectionFailed(let m): return "Connection failed: \(m)"
            case .timedOut:                return "The server did not respond in time."
            case .malformedResponse:       return "The server sent a malformed response."
            case .malformedRequest:        return "The request could not be encoded safely."
            case .responseTooLarge:        return "The server sent more data than expected."
            }
        }
    }

    /// The control plane's largest response is a few hundred bytes.
    ///
    /// Without a ceiling a server — or anything that has taken its place — could
    /// stream until the client runs out of memory, and the client would keep
    /// accepting it because nothing said to stop.
    private static let maxResponseBytes = 256 * 1024

    /// Rejects values that would break out of their header.
    private func isHeaderSafe(_ value: String) -> Bool {
        !value.contains("\r") && !value.contains("\n") && !value.contains("\0")
    }

    struct Response {
        let status: Int
        let body: Data
    }

    private let host: String
    private let port: UInt16
    /// Whether a certificate outside the system's trust store is acceptable.
    ///
    /// Consulted per connection rather than captured once. It was read at
    /// construction, before the user had necessarily pinned anything, so a pin
    /// added afterwards did not take effect until the app was relaunched — and
    /// the failure looked like a rejected pin rather than a stale policy.
    private let acceptAnyCertificate: @Sendable () -> Bool

    init(host: String, port: UInt16, acceptAnyCertificate: @escaping @Sendable () -> Bool) {
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

        if acceptAnyCertificate() {
            // Accepting any certificate was justified by the WireGuard key pin
            // checked after the response is parsed. That argument covers the
            // tunnel: an interceptor must return the pinned key, and if they do
            // the handshake fails because they lack the private half.
            //
            // It does not cover this connection's contents. `POST /v1/peers`
            // carries a Privacy Pass token in a header, and an interceptor who
            // reads it can spend it — the pin, checked afterwards and only on
            // the config response, never sees that request. So the certificate
            // itself is pinned on first use as well: the first connection to a
            // self-signed server records its public key, and a different one
            // afterwards is refused.
            let host = self.host
            sec_protocol_options_set_verify_block(
                tls.securityProtocolOptions,
                { _, trust, complete in
                    let secTrust = sec_trust_copy_ref(trust).takeRetainedValue()
                    complete(CertificatePin.accepts(secTrust, host: host))
                },
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
        // A header value containing CR or LF ends the header and starts
        // whatever follows it, so one crafted value turns a request into two.
        // The Authorization value here is a token from a subprocess's stdout,
        // which is exactly the kind of input that should not be trusted to
        // contain no newlines.
        guard isHeaderSafe(method), isHeaderSafe(path),
              headers.allSatisfy({ isHeaderSafe($0.key) && isHeaderSafe($0.value) }) else {
            completion(.failure(Failure.malformedRequest))
            return
        }

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
            self.receiveAll(connection, into: Buffer(), completion: completion)
        })
    }

    /// Reads until the peer closes, bounded.
    ///
    /// `accumulated` is a class box rather than a passed-along value: appending
    /// to a `Data` parameter and handing the result to the next call copied the
    /// whole response on every chunk, so a large reply cost time quadratic in
    /// its size on top of the memory.
    private func receiveAll(
        _ connection: NWConnection,
        into accumulated: Buffer,
        completion: @escaping (Result<Response, Error>) -> Void
    ) {
        connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { chunk, _, isComplete, error in
            if let error {
                completion(.failure(Failure.connectionFailed(error.localizedDescription)))
                return
            }
            if let chunk { accumulated.data.append(chunk) }
            if accumulated.data.count > Self.maxResponseBytes {
                connection.cancel()
                completion(.failure(Failure.responseTooLarge))
                return
            }

            if isComplete {
                if let parsed = Self.parse(accumulated.data) {
                    completion(.success(parsed))
                } else {
                    completion(.failure(Failure.malformedResponse))
                }
                return
            }
            self.receiveAll(connection, into: accumulated, completion: completion)
        }
    }

    /// Mutable accumulation shared across the receive callbacks.
    private final class Buffer: @unchecked Sendable {
        var data = Data()
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
