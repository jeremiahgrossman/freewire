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
