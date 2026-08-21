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
    /// NWPathMonitor delivers its first path asynchronously, so this waits
    /// briefly for it rather than reading a path that has not arrived. A
    /// timeout reports reachable: refusing to try because the check was slow
    /// would be worse than attempting a connection that then fails properly.
    static func hasNetwork(timeout: TimeInterval = 1.0) -> Bool {
        let monitor = NWPathMonitor()
        let queue = DispatchQueue(label: "com.freewire.netmon.oneshot", qos: .userInitiated)
        let sema = DispatchSemaphore(value: 0)

        let lock = NSLock()
        var satisfied = true
        var reported = false

        monitor.pathUpdateHandler = { path in
            lock.lock()
            if !reported {
                reported = true
                satisfied = (path.status == .satisfied)
                lock.unlock()
                sema.signal()
                return
            }
            lock.unlock()
        }
        monitor.start(queue: queue)
        _ = sema.wait(timeout: .now() + timeout)
        monitor.cancel()

        lock.lock(); defer { lock.unlock() }
        return satisfied
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
