import Foundation
import Network

@MainActor
final class NetworkMonitor {
    private var monitor: NWPathMonitor?
    private let queue = DispatchQueue(label: "com.freewire.netmon", qos: .utility)
    private var lastSatisfied: Bool?

    // Annotated @MainActor so Swift 6 allows callers to assign closures that
    // access @MainActor-isolated state, and allows handle() to call them safely.
    var onNetworkAvailable: (@MainActor () -> Void)?
    var onNetworkUnavailable: (@MainActor () -> Void)?

    /// One-shot reachability check, for deciding CONN-1 before a connect attempt.
    ///
    /// NWPathMonitor delivers its first path asynchronously, so this waits for
    /// it rather than reading a path that has not arrived. A timeout reports
    /// reachable: refusing to try because the check was slow would be worse
    /// than attempting a connection that then fails properly.
    ///
    /// Async rather than blocking on a semaphore. Every connect attempt begins
    /// with this call, and the blocking version ran on the main actor: the
    /// whole UI froze for up to a second each time the user pressed Connect,
    /// and again on every automatic retry, which is exactly when the interface
    /// most needs to stay responsive.
    static func hasNetwork(timeout: TimeInterval = 1.0) async -> Bool {
        let monitor = NWPathMonitor()
        let queue = DispatchQueue(label: "com.freewire.netmon.oneshot", qos: .userInitiated)

        let result: Bool = await withCheckedContinuation { cont in
            let once = ResumeOnce(cont)
            monitor.pathUpdateHandler = { path in
                once.resume(with: path.status == .satisfied)
            }
            monitor.start(queue: queue)
            // Timing out reports reachable, so a slow check never blocks a
            // connect the user asked for.
            queue.asyncAfter(deadline: .now() + timeout) { once.resume(with: true) }
        }
        monitor.cancel()
        return result
    }

    /// Resumes a continuation at most once, from any queue.
    ///
    /// The path handler and the timeout fire independently, and resuming a
    /// CheckedContinuation twice is an unconditional fatalError.
    private final class ResumeOnce: @unchecked Sendable {
        private let lock = NSLock()
        private var cont: CheckedContinuation<Bool, Never>?

        init(_ cont: CheckedContinuation<Bool, Never>) { self.cont = cont }

        func resume(with value: Bool) {
            lock.lock()
            let c = cont
            cont = nil
            lock.unlock()
            c?.resume(returning: value)
        }
    }

    func start() {
        let m = NWPathMonitor()
        // pathUpdateHandler fires on `queue` (not @MainActor).
        // Task { @MainActor } hops to the main actor before touching any @MainActor state.
        // DispatchQueue.main.async does NOT satisfy @MainActor isolation in Swift 6.
        m.pathUpdateHandler = { [weak self] path in
            Task { @MainActor [weak self] in self?.handle(path) }
        }
        m.start(queue: queue)
        monitor = m
    }

    func stop() {
        monitor?.cancel()
        monitor = nil
        lastSatisfied = nil
    }

    private func handle(_ path: NWPath) {
        let satisfied = path.status == .satisfied
        guard satisfied != lastSatisfied else { return }
        lastSatisfied = satisfied
        if satisfied { onNetworkAvailable?() } else { onNetworkUnavailable?() }
    }
}
