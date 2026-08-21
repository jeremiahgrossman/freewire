import Foundation
import Network

// Runs silently after a tunnel is established on any path. Probes for faster paths
// and notifies TunnelManager when an upgrade is available.
//
// Path priority (fastest → slowest):
//   1. Open WireGuard (UDP 51820)
//   2. HTTP CONNECT
//   3. TLS/443
//   4. DNS tunnel
//   5. ICMP/UDP
//
// The manager only upgrades, never downgrades. It probes in parallel, picks the
// fastest available path, and hands the result back via the onUpgradeAvailable callback.
// TunnelManager performs the actual migration by restarting the tunnel binary.

@MainActor
final class PathUpgradeManager {

    // Called when a faster path is confirmed reachable. Argument is the transport name
    // (matching freewire-tunnel JSON values: "wireguard", "tls443", "http_connect", etc.).
    var onUpgradeAvailable: (@MainActor (TunnelTransport) -> Void)?

    private let serverHost: String
    private let wgPort: Int
    private var probeTask: Task<Void, Never>?
    private var currentTransport: TunnelTransport

    init(serverHost: String, wgPort: Int = 51820, currentTransport: TunnelTransport) {
        self.serverHost = serverHost
        self.wgPort = wgPort
        self.currentTransport = currentTransport
    }

    func start() {
        guard currentTransport != .wireguard else { return } // already fastest
        probeTask = Task { await self.runSchedule() }
    }

    func stop() {
        probeTask?.cancel()
        probeTask = nil
    }

    func didUpgrade(to transport: TunnelTransport) {
        currentTransport = transport
        if transport == .wireguard {
            stop() // at fastest path, no more probing needed
        }
    }

    // MARK: - Probe schedule (per spec §Re-probe Schedule)

    private func runSchedule() async {
        let start = Date()
        while !Task.isCancelled {
            let elapsed = Date().timeIntervalSince(start)
            let interval: TimeInterval
            switch elapsed {
            case ..<300:    interval = 60
            case ..<1800:   interval = 120
            default:        interval = 300
            }
            try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
            guard !Task.isCancelled else { return }
            await probeForUpgrade()
        }
    }

    // MARK: - Probe

    private func probeForUpgrade() async {
        // Collect candidates faster than current path.
        let candidates = TunnelTransport.allCases.filter { $0.priority < currentTransport.priority }
        guard !candidates.isEmpty else { return }

        // Probe all candidates in parallel with a 2s deadline.
        let results = await withTaskGroup(of: (TunnelTransport, Bool).self) { group in
            for candidate in candidates {
                group.addTask { [weak self] in
                    guard let self else { return (candidate, false) }
                    let reachable = await self.probe(candidate)
                    return (candidate, reachable)
                }
            }
            var found: [(TunnelTransport, Bool)] = []
            for await result in group { found.append(result) }
            return found
        }

        // Pick fastest reachable path.
        if let best = results
            .filter({ $0.1 })
            .min(by: { $0.0.priority < $1.0.priority }) {
            onUpgradeAvailable?(best.0)
        }
    }

    private func probe(_ transport: TunnelTransport) async -> Bool {
        switch transport {
        case .wireguard:
            return await probeWireGuard()
        case .tls443, .httpConnect:
            return await probeTCP443()
        case .dns:
            return false // DNS tunnel probe would require full handshake; skip in upgrade manager
        case .icmpUDP:
            return false
        }
    }

    private func probeWireGuard() async -> Bool {
        // UDP reachability probe: send a zero-byte UDP datagram to the WireGuard port.
        // If the port is open, the OS won't immediately return ECONNREFUSED.
        // This is a best-effort heuristic — the upgrade manager accepts false positives
        // (TunnelManager will detect the failure and stay on the current path).
        return await withCheckedContinuation { cont in
            let conn = NWConnection(
                host: NWEndpoint.Host(serverHost),
                port: NWEndpoint.Port(integerLiteral: UInt16(wgPort)),
                using: .udp
            )
            var done = false
            let finish = { (result: Bool) in
                guard !done else { return }
                done = true
                conn.cancel()
                cont.resume(returning: result)
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:   finish(true)
                case .failed:  finish(false)
                default: break
                }
            }
            conn.start(queue: .global())
            // 2s deadline
            DispatchQueue.global().asyncAfter(deadline: .now() + 2) { finish(false) }
        }
    }

    private func probeTCP443() async -> Bool {
        return await withCheckedContinuation { cont in
            let conn = NWConnection(
                host: NWEndpoint.Host(serverHost),
                port: 443,
                using: .tcp
            )
            var done = false
            let finish = { (result: Bool) in
                guard !done else { return }
                done = true
                conn.cancel()
                cont.resume(returning: result)
            }
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:   finish(true)
                case .failed:  finish(false)
                default: break
                }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 2) { finish(false) }
        }
    }
}

// MARK: - TunnelTransport

enum TunnelTransport: String, CaseIterable {
    case wireguard  = "wireguard"
    case httpConnect = "http_connect"
    case tls443     = "tls443"
    case dns        = "dns"
    case icmpUDP    = "icmp_udp"

    /// Lower = faster. Upgrade manager only upgrades toward lower priority numbers.
    var priority: Int {
        switch self {
        case .wireguard:   return 1
        case .httpConnect: return 2
        case .tls443:      return 3
        case .dns:         return 4
        case .icmpUDP:     return 5
        }
    }

    /// True when throughput is constrained (DNS or ICMP tunnel).
    var isReducedSpeed: Bool {
        self == .dns || self == .icmpUDP
    }

    var displayName: String {
        switch self {
        case .wireguard:   return "WireGuard"
        case .httpConnect: return "HTTP CONNECT"
        case .tls443:      return "TLS/443"
        case .dns:         return "DNS tunnel"
        case .icmpUDP:     return "ICMP tunnel"
        }
    }
}
