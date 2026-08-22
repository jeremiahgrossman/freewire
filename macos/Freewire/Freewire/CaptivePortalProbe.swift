import Foundation

// Probe `http://captive.apple.com` to distinguish:
//   CONN-2a: captive portal intercepting traffic (need to authenticate)
//   CONN-2b: genuine network block (no portal)
// Runs only after the tunnel binary exhausts all four transport paths.

enum CaptivePortalResult {
    case captivePortal(redirectURL: URL?)
    case genuineBlock
}

func probeCaptivePortal() async -> CaptivePortalResult {
    guard let url = URL(string: "http://captive.apple.com/hotspot-detect.html") else {
        return .genuineBlock
    }

    let result = await withCheckedContinuation { (cont: CheckedContinuation<CaptivePortalResult, Never>) in
        let delegate = NoRedirectDelegate(continuation: cont)
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest  = 1.0
        cfg.timeoutIntervalForResource = 1.0
        let session = URLSession(configuration: cfg, delegate: delegate, delegateQueue: nil)
    // URLSession retains its delegate until invalidated, so a probe per
    // connection attempt leaked a session and a delegate each time.
    defer { session.finishTasksAndInvalidate() }
        var req = URLRequest(url: url)
        req.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData

        let task = session.dataTask(with: req) { data, response, error in
            // Redirect was already handled in the delegate — if we get here,
            // the response is the final one (no redirect, or portal showed its page).
            if error != nil {
                delegate.resume(with: .genuineBlock)
                return
            }
            guard let http = response as? HTTPURLResponse else {
                delegate.resume(with: .genuineBlock)
                return
            }
            // 200 with Apple's exact "Success" body means no portal.
            if http.statusCode == 200, let body = data.flatMap({ String(data: $0, encoding: .utf8) }),
               body.contains("Success") {
                delegate.resume(with: .genuineBlock)
            } else {
                delegate.resume(with: .captivePortal(redirectURL: nil))
            }
        }
        task.resume()
    }
    return result
}

// URLSession delegate that intercepts 3xx redirects — a redirect is the portal signal.
private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    private var cont: CheckedContinuation<CaptivePortalResult, Never>?
    private var resumed = false
    private let lock = NSLock()

    init(continuation: CheckedContinuation<CaptivePortalResult, Never>) {
        self.cont = continuation
    }

    func resume(with result: CaptivePortalResult) {
        lock.lock()
        defer { lock.unlock() }
        guard !resumed else { return }
        resumed = true
        cont?.resume(returning: result)
        cont = nil
    }

    // Called before following a redirect. Returning nil prevents the redirect
    // and signals to the data task that the response is done.
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        // Redirect = captive portal; capture Location if present.
        let location = response.value(forHTTPHeaderField: "Location").flatMap { URL(string: $0) }
        resume(with: .captivePortal(redirectURL: location))
        completionHandler(nil) // don't follow the redirect
    }
}
