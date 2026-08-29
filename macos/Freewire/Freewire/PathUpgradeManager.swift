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
    /// DNS-tunnel zone, needed for the `.dns` upgrade probe (server-direct DNS
    /// handshake). Nil falls back to the helper's default zone, which is correct
    /// for the default deployment; a custom self-hosted zone left nil only makes
    /// the probe a false negative (a missed DNS upgrade), never a bad one.
    private let dnsTunnelDomain: String?
    /// The rootless tunnel helper, used to run the `.dns` upgrade probe. Injected
    /// (rather than resolved here) so this type has no dependency on TunnelManager
    /// and stays compilable on its own for the standalone test harness. Nil
    /// disables the DNS probe (it reports unreachable), which is safe.
    private let helperURL: URL?
    /// Port the udp443 carrier (WireGuard over UDP/443) listens on, for the
    /// `.udp443` magic probe. Defaults to 443; a self-hosted server on another
    /// port supplies it from the cache.
    private let udp443Port: Int
    private var probeTask: Task<Void, Never>?
    private var currentTransport: TunnelTransport

    init(serverHost: String, wgPort: Int = 51820, currentTransport: TunnelTransport,
         dnsTunnelDomain: String? = nil, helperURL: URL? = nil, udp443Port: Int = 443) {
        self.serverHost = serverHost
        self.wgPort = wgPort
        self.currentTransport = currentTransport
        self.dnsTunnelDomain = dnsTunnelDomain
        self.helperURL = helperURL
        self.udp443Port = udp443Port
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
        case .udp443:
            return await probeUDP443()
        case .tls443:
            return await probeTCP443()
        case .cdnWSS:
            // Same reasoning as wss443, and more so: reaching the CDN edge on 443
            // says nothing about whether the fronted path carries traffic, and
            // the chain discovers it correctly on connect.
            return false
        case .wss443:
            // Reaching TCP/443 is necessary but not sufficient: the whole point
            // of this carrier is the networks that accept a completed HTTP
            // Upgrade while resetting a raw TLS session on the same port, and a
            // bare TCP probe cannot tell those apart. Upgrading to it on a TCP
            // probe alone would mean upgrading onto a path that may not carry
            // traffic. The chain already discovers it correctly on connect, so
            // the upgrade manager declines rather than guesses.
            return false
        case .httpConnect:
            return await probeHTTPConnect()
        case .dns:
            return await probeDNS()
        case .icmpUDP:
            // ICMP is the slowest path, so it is never a candidate here (the
            // candidate filter keeps only paths faster than the current one, and
            // nothing is slower than ICMP). This arm is unreachable in practice;
            // it stays false so a future reordering cannot turn it into a probe
            // that would need raw sockets (root) the app does not have anyway.
            return false
        }
    }

    /// Probes the DNS tunnel by running the helper's rootless `--dns-probe`,
    /// which completes the full DNS-carrier handshake against the server plus a
    /// post-handshake poll and changes no system state, so it is safe on a
    /// machine in use.
    ///
    /// Server-direct (resolver = the server itself): the server IP is pinned
    /// outside the tunnel, so the probe takes the real DIRECT path rather than
    /// looping back through the active tunnel, and field testing showed
    /// server-direct is the DNS path that actually carries traffic (the
    /// public-recursor path throttles below usable). A full handshake, not a bare
    /// UDP/53 reachability ping: a false positive tears down a working tunnel to
    /// rebuild on a DNS path that then fails, so the probe must prove the carrier
    /// is live, not merely that a datagram left the host.
    ///
    /// This is the one slow-path upgrade with a sufficient rootless probe, and it
    /// fires only from the ICMP tunnel (the sole path slower than DNS). Every
    /// faster slow-path target -- wireguard, udp443, wss443, cdn_wss -- still
    /// declines above, because a cheap probe cannot predict whether they carry
    /// traffic and the connect chain discovers them correctly instead.
    private func probeDNS() async -> Bool {
        guard let binary = helperURL else { return false }
        var args = ["--dns-probe", "--resolver", serverHost]
        if let zone = dnsTunnelDomain, !zone.isEmpty {
            args.append(contentsOf: ["--domain", zone])
        }
        // The DNS handshake is three round trips at ~1s each; the fallback chain
        // budgets it at 3s, so hold the probe to the same ceiling rather than the
        // generic 2s the TCP probes use.
        return await Self.runProbeBinary(binary, args: args, timeout: 3)
    }

    /// Runs a rootless helper subcommand off the main actor and reports whether
    /// it exited 0 within `timeout`, terminating it if it overruns.
    ///
    /// Carrier handshake protocols (DNS, ICMP) live in the Go helper; driving its
    /// `--dns-probe` reuses that tested code rather than reimplementing the
    /// protocol in Swift. Output is discarded -- the exit status is the whole
    /// signal, and the helper never logs a client IP.
    nonisolated private static func runProbeBinary(_ url: URL, args: [String], timeout: TimeInterval) async -> Bool {
        await Task.detached(priority: .utility) {
            let p = Process()
            p.executableURL = url
            p.arguments = args
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            guard (try? p.run()) != nil else { return false }

            // Enforce the deadline: terminate a probe that overruns rather than
            // let a stalled handshake hold the upgrade round open. Cancelled if
            // the process finishes first.
            let killer = DispatchWorkItem { if p.isRunning { p.terminate() } }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: killer)
            p.waitUntilExit()
            killer.cancel()
            return p.terminationStatus == 0
        }.value
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
        // Deliberately reports unreachable, and cannot be safely made otherwise
        // from the client alone.
        //
        // A UDP .ready check is a false positive (UDP is connectionless;
        // NWConnection reaches .ready without a packet leaving the host), which
        // is the bug this replaced. The only sufficient test is a real WireGuard
        // handshake -- but that would use the device's static key, and a second
        // authenticated handshake from the direct 51820 path makes the server
        // ROAM the peer's endpoint there (WireGuard's roaming). The server would
        // then send the peer's traffic to a direct socket the probe never routed,
        // tearing down the active carrier-based session. There is no magic
        // responder on 51820 either (WireGuard owns the port), so no cheap
        // key-less probe exists.
        //
        // udp443 IS WireGuard, just on UDP/443, and it has a key-less magic probe
        // (probeUDP443) plus line-rate throughput (~125 Mbps, no TCP-over-TCP). A
        // network that passes UDP/51820 almost always passes UDP/443, so probing
        // udp443 captures the WireGuard-speed upgrade without the roaming hazard.
        return false
    }

    /// Probes udp443 (WireGuard straight over UDP/443) with the server's magic
    /// UDP reachability probe -- the same signal the connect-time probe battery
    /// uses to decide udp443. The udp443 listener dispatches a magic datagram to
    /// its echo responder, so a returned nonce proves the portal passes UDP/443
    /// to our server AND the carrier's dispatcher is live; the WireGuard handshake
    /// that follows is between tested code and the same server, so reachability is
    /// the sufficient test. One round trip, rootless, and -- unlike a real
    /// WireGuard handshake -- it carries no WireGuard identity, so it cannot roam
    /// the active session's endpoint (see probeWireGuard). The server IP is pinned
    /// outside the tunnel, so the datagram takes the real DIRECT path.
    private func probeUDP443() async -> Bool {
        await Self.magicUDPReachable(host: serverHost, port: udp443Port, timeout: 2)
    }

    /// Sends the server's magic UDP probe and reports whether the echoed nonce
    /// comes back within `timeout`. A pass requires the matching reply, never
    /// merely a .ready UDP connection (connectionless, so .ready proves nothing).
    nonisolated private static func magicUDPReachable(host: String, port: Int, timeout: TimeInterval) async -> Bool {
        var nonce = [UInt8](repeating: 0, count: MagicProbe.nonceLen)
        for i in nonce.indices { nonce[i] = UInt8.random(in: .min ... .max) }
        let request = MagicProbe.request(nonce: nonce)

        return await withCheckedContinuation { cont in
            // The guard is crossed by the connection's callback queue and the
            // timeout block on different threads; resuming a continuation twice
            // is a fatalError, so serialize with a lock.
            let lock = NSLock()
            var done = false
            let finish: (Bool) -> Void = { result in
                lock.lock(); if done { lock.unlock(); return }; done = true; lock.unlock()
                cont.resume(returning: result)
            }

            let conn = NWConnection(
                host: NWEndpoint.Host(host),
                port: NWEndpoint.Port(integerLiteral: UInt16(port)),
                using: .udp
            )
            conn.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    conn.send(content: Data(request), completion: .contentProcessed { error in
                        if error != nil { conn.cancel(); finish(false); return }
                        conn.receiveMessage { data, _, _, _ in
                            let ok = data.map { MagicProbe.replyMatches([UInt8]($0), nonce: nonce) } ?? false
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
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                conn.cancel()
                finish(false)
            }
        }
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

// MARK: - MagicProbe

/// Wire codec for the server's magic UDP reachability probe (the udp443 upgrade
/// probe, and what the connect-time probe battery uses).
///
/// Must match the server's `probeMagic` / `probeNonceLen` / `probeMinRequest`
/// (server/internal/transport/probe.go and udp443.go). Pulled out as a pure
/// codec so it is testable at the desk without a live server; the network glue
/// (magicUDPReachable) stays in the manager.
enum MagicProbe {
    /// Opens every request and reply. Must equal the server's probeMagic.
    static let magic = Array("FWPROBE1".utf8)
    /// Nonce length the client supplies and the server echoes (probeNonceLen).
    static let nonceLen = 16
    /// Minimum request size; the reply is always smaller, so the responder can
    /// never amplify. Clients pad up to this (probeMinRequest).
    static let minRequest = 64

    /// Builds a probe request: magic + nonce, zero-padded to the server minimum.
    static func request(nonce: [UInt8]) -> [UInt8] {
        var req = magic + nonce
        if req.count < minRequest {
            req.append(contentsOf: repeatElement(0, count: minRequest - req.count))
        }
        return req
    }

    /// True when a reply echoes our nonce after the magic prefix. A datagram that
    /// does not echo the nonce is an unrelated packet on the port, not a pass.
    static func replyMatches(_ reply: [UInt8], nonce: [UInt8]) -> Bool {
        guard reply.count >= magic.count + nonceLen else { return false }
        return Array(reply.prefix(magic.count)) == magic
            && Array(reply[magic.count ..< magic.count + nonceLen]) == nonce
    }
}

// MARK: - TunnelTransport

enum TunnelTransport: String, CaseIterable {
    case wireguard  = "wireguard"
    case udp443     = "udp443"
    case httpConnect = "http_connect"
    case tls443     = "tls443"
    case wss443     = "wss443"
    case cdnWSS     = "cdn_wss"
    case dns        = "dns"
    case icmpUDP    = "icmp_udp"

    /// Lower = faster. Upgrade manager only upgrades toward lower priority numbers.
    ///
    /// Must match the chain's speed order in tunnel/cmd/freewire-tunnel/transport.go
    /// (defaultCandidates). A mismatch here does not fail loudly: it silently
    /// makes the upgrade manager chase the wrong path.
    var priority: Int {
        switch self {
        case .wireguard:   return 1
        case .udp443:      return 2
        case .httpConnect: return 3
        case .tls443:      return 4
        case .wss443:      return 5
        case .cdnWSS:      return 6
        case .dns:         return 7
        case .icmpUDP:     return 8
        }
    }

    /// True when throughput is constrained (DNS or ICMP tunnel).
    var isReducedSpeed: Bool {
        self == .dns || self == .icmpUDP
    }

    /// True when encrypted DNS is not in use on this transport.
    ///
    /// DoH costs a full HTTPS round trip per uncached lookup, which these two
    /// deliver in 5-10 seconds. Since the takeover is system-wide, every
    /// application pays it, so the tunnel leaves the resolver alone here and the
    /// network can see which sites are visited. DNS-1 in error-states-spec.md;
    /// the reasoning is in DECISIONS.md under DNS-ON-SLOW-TRANSPORTS.
    var leaksDNSToNetwork: Bool {
        self == .dns || self == .icmpUDP
    }

    var displayName: String {
        switch self {
        case .wireguard:   return "WireGuard"
        case .udp443:      return "WireGuard UDP/443"
        case .httpConnect: return "HTTP CONNECT"
        case .tls443:      return "TLS/443"
        case .wss443:      return "WebSocket/443"
        case .cdnWSS:      return "CDN WebSocket/443"
        case .dns:         return "DNS tunnel"
        case .icmpUDP:     return "ICMP tunnel"
        }
    }
}
