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
        case .tls443:
            return await probeTCP443()
        case .httpConnect:
            return await probeHTTPConnect()
        case .dns:
            return false // DNS tunnel probe would require full handshake; skip in upgrade manager
        case .icmpUDP:
            return false
        }
    }

    /// HTTP CONNECT depends on a proxy running on the local gateway, not on the
    /// VPN server. Probing the server's TCP/443 proved only that TLS/443 works,
    /// so this path reported reachable on every network where TLS already was.
    private func probeHTTPConnect() async -> Bool {
        guard let gateway = await Self.defaultGateway() else { return false }

        for port in [3128, 8080] {
            if await Self.connectSucceeds(host: gateway, port: port, target: serverHost) { return true }
        }
        return false
    }

    /// Opens a CONNECT tunnel to the VPN endpoint through host:port and reports
    /// whether the proxy answered 200.
    private static func connectSucceeds(host: String, port: Int, target serverHost: String) async -> Bool {
        await withCheckedContinuation { cont in
            // See the note above: this guard is crossed by two queues.
            let lock = NSLock()
            var done = false
            let finish: (Bool) -> Void = { result in
                lock.lock()
                if done { lock.unlock(); return }
                done = true
                lock.unlock()
                cont.resume(returning: result)
            }

            let conn = NWConnection(
                host: NWEndpoint.Host(host),
                port: NWEndpoint.Port(integerLiteral: UInt16(port)),
                using: .tcp
            )

            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    // The configured server, not a hardcoded hostname. Asking
                    // the proxy for vpn.freewire.com tested whether it would
                    // reach a host the tunnel never uses: against a self-hosted
                    // server the probe reported a path that does not exist, and
                    // the upgrade it triggered tore down a working tunnel to
                    // rebuild it on one that could not connect.
                    let target = "\(serverHost):443"
                    let request = "CONNECT \(target) HTTP/1.1\r\n" +
                                  "Host: \(target)\r\n\r\n"
                    conn.send(content: Data(request.utf8), completion: .contentProcessed { error in
                        if error != nil {
                            conn.cancel(); finish(false); return
                        }
                        conn.receive(minimumIncompleteLength: 1, maximumLength: 256) { data, _, _, _ in
                            let ok = data.flatMap { String(data: $0, encoding: .utf8) }?
                                .hasPrefix("HTTP/1.1 200") ?? false
                            conn.cancel()
                            finish(ok)
                        }
                    })
                case .failed, .cancelled:
                    conn.cancel(); finish(false)
                default:
                    break
                }
            }
            conn.start(queue: .global())

            // The whole path is budgeted at 2s in the fallback chain; hold the
            // probe to the same ceiling.
            DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
                conn.cancel()
                finish(false)
            }
        }
    }

    /// Parses `route get default` for the gateway address.
    ///
    /// Detached rather than run inline. It forks a process and waits for it,
    /// and every upgrade probe calls it -- on the main actor that froze the UI
    /// for the duration, on a schedule, for the whole life of a connection.
    private static func defaultGateway() async -> String? {
        await Task.detached(priority: .utility) { defaultGatewaySync() }.value
    }

    nonisolated private static func defaultGatewaySync() -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/sbin/route")
        p.arguments = ["-n", "get", "default"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return nil }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard let out = String(data: data, encoding: .utf8) else { return nil }

        for line in out.split(separator: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("gateway:") {
                let value = t.dropFirst("gateway:".count).trimmingCharacters(in: .whitespaces)
                return value.isEmpty ? nil : value
            }
        }
        return nil
    }

    private func probeWireGuard() async -> Bool {
        // Not implemented, and deliberately reports unreachable.
        //
        // The previous version opened a UDP NWConnection to the WireGuard port
        // and treated .ready as success. UDP is connectionless: NWConnection
        // reaches .ready without a single packet leaving the host, so this
        // returned true on every network including ones blocking UDP outright.
        // The upgrade manager then restarted the tunnel about 60s after every
        // connect, failed to reach WireGuard, and repeated.
        //
        // A real probe has to send a WireGuard handshake initiation and wait
        // for the response, which needs the peer keys the manager does not
        // hold. Until that exists, reporting unreachable keeps the client on
        // the working path rather than acting on a probe that cannot fail.
        return false
    }

    private func probeTCP443() async -> Bool {
        return await withCheckedContinuation { cont in
            let conn = NWConnection(
                host: NWEndpoint.Host(serverHost),
                port: 443,
                using: .tcp
            )
            // `done` is touched from the NWConnection callback queue and from the
            // timeout block below, on different threads. An unsynchronized
            // check-then-set lets both pass the guard and resume the
            // continuation twice, which is an unconditional fatalError.
            let lock = NSLock()
            var done = false
            let finish = { (result: Bool) in
                lock.lock()
                if done { lock.unlock(); return }
                done = true
                lock.unlock()
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
