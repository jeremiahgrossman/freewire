import AppKit
import Foundation
import Combine

// MARK: - State

enum TunnelState {
    case disconnected
    case connecting(status: String)
    case connected(tunnelIP: String, interfaceName: String, connectedAt: Date, transport: TunnelTransport)
    case reconnecting(attempt: Int)   // traffic NOT blocked: kill switch unimplemented
    case blocked                      // all reconnect attempts failed
    case captivePortal(redirectURL: URL?)  // CONN-2a: portal intercepting, need auth
    case networkBlock                 // CONN-2b: hard block, no portal
    case failed(Error)

    var iconSymbol: String {
        switch self {
        case .disconnected, .failed:   return "network"
        case .connecting:              return "network.badge.shield.half.filled"
        case .connected:               return "checkmark.shield.fill"
        case .reconnecting:            return "exclamationmark.triangle.fill"
        case .blocked, .networkBlock:  return "xmark.shield.fill"
        case .captivePortal:           return "wifi.exclamationmark"
        }
    }
}

// MARK: - Manager

/// Lock-guarded box for the active peer token.
///
/// Termination handlers run on the main thread and cannot `await` a main-actor
/// property without deadlocking, so the token is mirrored here where any thread
/// can read it synchronously.
final class PeerTokenBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?

    var token: String? {
        get { lock.lock(); defer { lock.unlock() }; return value }
        set { lock.lock(); defer { lock.unlock() }; value = newValue }
    }
}

@MainActor
final class TunnelManager: ObservableObject {
    @Published private(set) var state: TunnelState = .disconnected

    private let api: ServerAPI
    private let identity: DeviceIdentity
    let peerTokenBox = PeerTokenBox()

    private var peerToken: String? {
        get { peerTokenBox.token }
        set { peerTokenBox.token = newValue }
    }
    private var networkMonitor: NetworkMonitor?
    private var watchTask: Task<Void, Never>?
    private var reconnectTask: Task<Void, Never>?
    private var upgradeManager: PathUpgradeManager?
    private var awaitPortalTask: Task<Void, Never>?
    private var connectTask: Task<Void, Never>?

    init(api: ServerAPI, identity: DeviceIdentity) {
        self.api = api
        self.identity = identity
    }

    /// Certificate verification is skipped only for servers at a loopback or
    /// RFC 1918 literal address, where a self-signed development certificate is
    /// expected. Any routable host must present a valid CA-signed certificate.
    ///
    /// The address is parsed, never prefix-matched. An earlier version tested
    /// `hasPrefix("10.")` and friends against the raw host string, so routable
    /// names like `10.attacker.com` or `192.168.evil.net` disabled certificate
    /// verification for a public host.
    private var allowsSelfSignedCert: Bool {
        let h = api.serverHost
        if h == "::1" { return true }

        let parts = h.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        var octets: [Int] = []
        for p in parts {
            // Reject anything that is not a bare decimal octet, so a hostname
            // whose labels happen to be numeric cannot slip through.
            guard !p.isEmpty, p.allSatisfy(\.isNumber), let v = Int(p), (0...255).contains(v) else {
                return false
            }
            octets.append(v)
        }

        switch (octets[0], octets[1]) {
        case (127, _):            return true   // 127.0.0.0/8
        case (10, _):             return true   // 10.0.0.0/8
        case (192, 168):          return true   // 192.168.0.0/16
        case (172, 16...31):      return true   // 172.16.0.0/12
        default:                  return false
        }
    }

    // MARK: - Public API

    func connect() async {
        // `.failed` must be allowed through: the failure panel shows a Connect
        // button, and rejecting the call left that button visibly dead.
        switch state {
        case .disconnected, .failed:
            break
        default:
            return
        }
        // Held so cancelConnect can actually stop it. Previously the connect ran
        // as a detached task nothing retained, so Cancel set the state to
        // disconnected and the still-running connect overwrote it seconds later
        // with connected or failed.
        connectTask?.cancel()
        let task = Task { await doConnect() }
        connectTask = task
        await task.value
    }

    func cancelConnect() {
        connectTask?.cancel(); connectTask = nil
        watchTask?.cancel(); watchTask = nil
        reconnectTask?.cancel(); reconnectTask = nil
        state = .disconnected
        Task { await killTunnel(); await deregisterPeer() }
    }

    func disconnect() async {
        connectTask?.cancel(); connectTask = nil
        cancelTasks()
        stopUpgradeManager()
        state = .disconnected
        await killTunnel()
        await deregisterPeer()
        stopNetworkMonitor()
    }

    func retryFromBlocked() async {
        guard case .blocked = state else { return }
        reconnectTask = Task { await doReconnect(startingAt: 0) }
    }

    func retryFromNetworkBlock() async {
        state = .disconnected
        await doConnect()
    }

    // Opens the captive portal URL in the default browser so the user can authenticate.
    // Resets to disconnected so they can press Connect again after logging in.
    func openCaptivePortal(url: URL?) {
        let target = url ?? URL(string: "http://captive.apple.com")!
        NSWorkspace.shared.open(target)
        state = .disconnected

        // The panel tells the user Freewire will reconnect once they have
        // authenticated, so actually watch for that. Nothing here can tell when
        // the login completes, so poll the portal probe until the network comes
        // back or the user gives up.
        awaitPortalTask?.cancel()
        awaitPortalTask = Task { [weak self] in
            for _ in 0..<30 {   // ~90s at 3s intervals
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                guard let self, !Task.isCancelled else { return }
                guard case .disconnected = self.state else { return }
                if case .genuineBlock = await probeCaptivePortal() {
                    // No portal intercept any more: the login went through.
                    await self.doConnect()
                    return
                }
            }
        }
    }

    // MARK: - Connect

    private func doConnect() async {
        state = .connecting(status: "Finding the best path for this network.")

        do {
            let server = try await api.fetchConfig()

            guard server.capacityAvailable else {
                throw APIError.serverAtCapacity
            }

            let peer   = try await api.registerPeer(publicKeyBase64: identity.publicKeyBase64)
            peerToken  = peer.peerToken

            let cfg = TunnelConfig(
                privateKey:      identity.privateKeyBase64,
                serverPublicKey: server.publicKey,
                serverEndpoint:  server.endpoint,
                serverHost:      api.serverHost,
                tunnelIP:        peer.tunnelIP,
                serverTunnelIP:  "10.0.0.1",
                keepalive:       peer.keepaliveInterval,
                insecureTLS:     allowsSelfSignedCert,
                tlsPort:         server.tlsEndpointPort,
                dnsTunnelPort:   server.dnsTunnelPort,
                icmpUDPPort:     server.icmpUDPPort
            )

            let (ifName, transport) = try await launchTunnel(config: cfg)
            // The user may have cancelled while the helper was starting.
            guard !Task.isCancelled else {
                await killTunnel()
                await deregisterPeer()
                return
            }
            state = .connected(
                tunnelIP: peer.tunnelIP,
                interfaceName: ifName,
                connectedAt: Date(),
                transport: transport
            )
            startNetworkMonitor()
            startWatchdog()
            startUpgradeManager(serverHost: api.serverHost, transport: transport)

        } catch TunnelError.allPathsFailed {
            guard !Task.isCancelled else { await deregisterPeer(); return }
            // freewire-tunnel exhausted all four transport paths.
            // Probe captive.apple.com to distinguish portal (CONN-2a) from hard block (CONN-2b).
            await deregisterPeer()
            let probe = await probeCaptivePortal()
            switch probe {
            case .captivePortal(let url):
                state = .captivePortal(redirectURL: url)
            case .genuineBlock:
                state = .networkBlock
            }
        } catch {
            await deregisterPeer()
            guard !Task.isCancelled else { return }
            state = .failed(error)
        }
    }

    // MARK: - Reconnect

    private func doReconnect(startingAt attempt: Int) async {
        var attempt = attempt
        stopUpgradeManager()

        while attempt < 3 {
            guard !Task.isCancelled else { return }
            state = .reconnecting(attempt: attempt)

            await killTunnel()
            await deregisterPeer()

            do {
                let server = try await api.fetchConfig()
                let peer   = try await api.registerPeer(publicKeyBase64: identity.publicKeyBase64)
                peerToken  = peer.peerToken

                let cfg = TunnelConfig(
                    privateKey:      identity.privateKeyBase64,
                    serverPublicKey: server.publicKey,
                    serverEndpoint:  server.endpoint,
                    serverHost:      api.serverHost,
                    tunnelIP:        peer.tunnelIP,
                    serverTunnelIP:  "10.0.0.1",
                    keepalive:       peer.keepaliveInterval,
                    insecureTLS:     allowsSelfSignedCert,
                    tlsPort:         server.tlsEndpointPort,
                    dnsTunnelPort:   server.dnsTunnelPort,
                    icmpUDPPort:     server.icmpUDPPort
                )

                let (ifName, transport) = try await launchTunnel(config: cfg)
                state = .connected(
                    tunnelIP: peer.tunnelIP,
                    interfaceName: ifName,
                    connectedAt: Date(),
                    transport: transport
                )
                startNetworkMonitor()
                startWatchdog()
                startUpgradeManager(serverHost: api.serverHost, transport: transport)
                return

            } catch {
                attempt += 1
                if attempt < 3 {
                    let backoff: UInt64 = [2, 4, 8][attempt - 1] * 1_000_000_000
                    try? await Task.sleep(nanoseconds: backoff)
                }
            }
        }

        state = .blocked
    }

    // MARK: - Path upgrade manager

    private func startUpgradeManager(serverHost: String, transport: TunnelTransport) {
        guard transport != .wireguard else { return }
        let mgr = PathUpgradeManager(serverHost: serverHost, currentTransport: transport)
        mgr.onUpgradeAvailable = { [weak self] faster in
            guard let self else { return }
            Task { await self.performPathUpgrade(to: faster) }
        }
        upgradeManager = mgr
        mgr.start()
    }

    private func stopUpgradeManager() {
        upgradeManager?.stop()
        upgradeManager = nil
    }

    private func performPathUpgrade(to transport: TunnelTransport) async {
        guard case .connected(let ip, _, let at, let old) = state,
              transport.priority < old.priority else { return }
        upgradeManager?.stop()
        // The watchdog polls for the tunnel process. During an upgrade the
        // process is deliberately absent, and a watchdog firing in that window
        // would start a reconnect that races this upgrade.
        watchTask?.cancel(); watchTask = nil
        await killTunnel()
        await deregisterPeer()

        do {
            let server = try await api.fetchConfig()
            let peer   = try await api.registerPeer(publicKeyBase64: identity.publicKeyBase64)
            peerToken  = peer.peerToken

            let cfg = TunnelConfig(
                privateKey:      identity.privateKeyBase64,
                serverPublicKey: server.publicKey,
                serverEndpoint:  server.endpoint,
                serverHost:      api.serverHost,
                tunnelIP:        peer.tunnelIP,
                serverTunnelIP:  "10.0.0.1",
                keepalive:       peer.keepaliveInterval,
                insecureTLS:     allowsSelfSignedCert,
                tlsPort:         server.tlsEndpointPort,
                dnsTunnelPort:   server.dnsTunnelPort,
                icmpUDPPort:     server.icmpUDPPort
            )
            let (ifName, newTransport) = try await launchTunnel(config: cfg)
            state = .connected(
                tunnelIP: ip,
                interfaceName: ifName,
                connectedAt: at,
                transport: newTransport
            )
            startWatchdog()
            startUpgradeManager(serverHost: api.serverHost, transport: newTransport)
        } catch {
            reconnectTask?.cancel()
            reconnectTask = Task { await self.doReconnect(startingAt: 0) }
        }
    }

    // MARK: - Watchdog

    private func startWatchdog() {
        watchTask?.cancel()
        watchTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 5_000_000_000)
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 10_000_000_000)
                guard let self, case .connected = self.state else { return }

                let alive = await processAlive(name: "freewire-tunnel")
                if !alive {
                    self.stopUpgradeManager()
                    self.reconnectTask?.cancel()
                    self.reconnectTask = Task { await self.doReconnect(startingAt: 0) }
                    return
                }
            }
        }
    }

    private func processAlive(name: String) async -> Bool {
        await Task.detached(priority: .utility) { [name] in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
            p.arguments = ["-x", name]
            p.standardOutput = FileHandle.nullDevice
            p.standardError  = FileHandle.nullDevice
            try? p.run()
            p.waitUntilExit()
            return p.terminationStatus == 0
        }.value
    }

    // MARK: - Network monitor

    private func startNetworkMonitor() {
        let m = NetworkMonitor()
        m.onNetworkAvailable = { @MainActor [weak self] in
            guard let self else { return }
            if case .reconnecting = self.state {
                self.reconnectTask?.cancel()
                self.reconnectTask = Task { await self.doReconnect(startingAt: 0) }
            }
        }
        m.onNetworkUnavailable = { @MainActor [weak self] in
            guard let self else { return }
            // The tunnel cannot survive the interface going away. Without this
            // the panel kept showing "Protected" with a running timer until the
            // 10s watchdog poll noticed, which reads as the app lying.
            guard case .connected = self.state else { return }
            self.watchTask?.cancel(); self.watchTask = nil
            self.stopUpgradeManager()
            self.reconnectTask?.cancel()
            self.reconnectTask = Task { await self.doReconnect(startingAt: 0) }
        }
        m.start()
        networkMonitor = m
    }

    private func stopNetworkMonitor() {
        networkMonitor?.stop()
        networkMonitor = nil
    }

    // MARK: - Helpers

    private func cancelTasks() {
        watchTask?.cancel();       watchTask = nil
        reconnectTask?.cancel();   reconnectTask = nil
        awaitPortalTask?.cancel(); awaitPortalTask = nil
    }

    private func deregisterPeer() async {
        guard let token = peerToken else { return }
        peerToken = nil
        try? await api.removePeer(token: token)
    }

    private func killTunnel() async {
        await Task.detached(priority: .userInitiated) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
            p.arguments = ["/usr/bin/pkill", "-x", "freewire-tunnel"]
            p.standardOutput = FileHandle.nullDevice
            p.standardError  = FileHandle.nullDevice
            try? p.run()
            p.waitUntilExit()
        }.value
        try? await Task.sleep(nanoseconds: 300_000_000)
    }

    // MARK: - Tunnel launch

    private var tunnelHelperURL: URL? {
        if let bundled = Bundle.main.executableURL?
            .deletingLastPathComponent()
            .appendingPathComponent("freewire-tunnel"),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return bundled
        }
        #if DEBUG
        // Development convenience only. This path is under the user's home and
        // therefore user-writable, and the helper is executed via sudo — so it
        // must never be reachable in a release build.
        let dev = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Claude/Projects/FreewireVPN/tunnel/freewire-tunnel")
        return FileManager.default.isExecutableFile(atPath: dev.path) ? dev : nil
        #else
        return nil
        #endif
    }

    private func launchTunnel(config: TunnelConfig) async throws -> (String, TunnelTransport) {
        guard let helperURL = tunnelHelperURL else {
            throw TunnelError.helperNotFound
        }

        let tmp       = FileManager.default.temporaryDirectory
        let readyFile = tmp.appendingPathComponent("fw-ready-\(UUID().uuidString).txt")

        // The config carries the WireGuard private key, which must never touch
        // disk. It goes to the helper over a stdin pipe; only the ready line
        // comes back through a file.
        let configData = try JSONEncoder().encode(config)

        // sudo runs the helper binary directly. An earlier version wrote a
        // randomly-named shell script to the temp directory and ran sudo on
        // that, which made a scoped NOPASSWD sudoers rule impossible: the path
        // changed every launch, so the rule would have needed a wildcard over a
        // world-writable directory. Invoking the fixed binary path also closes
        // the window where that script existed on disk before it ran.
        let helperPath = helperURL.path
        let stderrPipe = Pipe()

        Task.detached { [helperPath, configData, readyFile, stderrPipe] in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
            // -n: never prompt. Without it sudo blocks on a password nobody can
            // type, the helper never starts, and the failure surfaces as an
            // empty error string.
            p.arguments = ["-n", helperPath]

            // The helper writes its ready line to stdout; redirect it to the file
            // the poller watches. Diagnostics from sudo itself arrive on stderr.
            FileManager.default.createFile(atPath: readyFile.path, contents: nil)
            if let out = try? FileHandle(forWritingTo: readyFile) {
                p.standardOutput = out
            }
            p.standardError = stderrPipe.fileHandleForWriting

            let stdin = Pipe()
            p.standardInput = stdin
            try? p.run()
            try? stdin.fileHandleForWriting.write(contentsOf: configData)
            try? stdin.fileHandleForWriting.close()
            p.waitUntilExit()
            try? stderrPipe.fileHandleForWriting.close()
        }

        func failure() -> TunnelError {
            let out = (try? String(contentsOf: readyFile, encoding: .utf8)) ?? ""
            let err = String(
                data: stderrPipe.fileHandleForReading.availableData,
                encoding: .utf8
            ) ?? ""
            try? FileManager.default.removeItem(at: readyFile)

            if out.contains("all_paths_failed") { return .allPathsFailed }

            let detail = (out + "\n" + err).trimmingCharacters(in: .whitespacesAndNewlines)
            if detail.isEmpty {
                return .helperFailed("The tunnel helper produced no output.")
            }
            // sudo's own refusal is the common case during development and is
            // otherwise reported as an unexplained failure.
            if detail.contains("a password is required") || detail.contains("a terminal is required") {
                return .helperNeedsPrivileges
            }
            return .helperFailed(detail)
        }

        do {
            let readyLine = try await pollReady(at: readyFile, timeout: 30)
            try? FileManager.default.removeItem(at: readyFile)

            // Line format: "ready <ifName> <tunnelIP> <transport>"
            let parts = readyLine.split(separator: " ")
            guard parts.count >= 2, parts[0] == "ready", !parts[1].isEmpty else {
                throw TunnelError.badReadyLine(readyLine)
            }
            let ifName = String(parts[1])
            let transport = parts.count >= 4
                ? TunnelTransport(rawValue: String(parts[3])) ?? .wireguard
                : .wireguard
            return (ifName, transport)
        } catch TunnelError.allPathsFailed {
            try? FileManager.default.removeItem(at: readyFile)
            throw TunnelError.allPathsFailed
        } catch {
            throw failure()
        }
    }

    private func pollReady(at url: URL, timeout: TimeInterval) async throws -> String {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if let text = try? String(contentsOf: url, encoding: .utf8) {
                let lines = text.components(separatedBy: "\n")
                if lines.contains(where: { $0.hasPrefix("all_paths_failed") }) {
                    throw TunnelError.allPathsFailed
                }
                if let line = lines.first(where: { $0.hasPrefix("ready ") }) {
                    return line
                }
            }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        throw TunnelError.timedOut
    }
}

// MARK: - Supporting types

private struct TunnelConfig: Encodable {
    let privateKey:      String
    let serverPublicKey: String
    let serverEndpoint:  String
    let serverHost:      String
    let tunnelIP:        String
    let serverTunnelIP:  String
    let keepalive:       Int
    let insecureTLS:     Bool
    let tlsPort:         Int
    let dnsTunnelPort:   Int
    let icmpUDPPort:     Int

    enum CodingKeys: String, CodingKey {
        case privateKey      = "private_key"
        case serverPublicKey = "server_public_key"
        case serverEndpoint  = "server_endpoint"
        case serverHost      = "server_host"
        case tunnelIP        = "tunnel_ip"
        case serverTunnelIP  = "server_tunnel_ip"
        case keepalive
        case insecureTLS     = "insecure_tls"
        case tlsPort         = "tls_port"
        case dnsTunnelPort   = "dns_tunnel_port"
        case icmpUDPPort     = "icmp_udp_port"
    }
}

enum TunnelError: Error, LocalizedError {
    case helperNotFound
    case helperNeedsPrivileges
    case helperFailed(String)
    case badReadyLine(String)
    case timedOut
    case allPathsFailed

    /// Copy is specified in error-states-spec.md under "Local tunnel failures
    /// (TUN)". Do not paraphrase: support matches reported text to spec entries.
    var errorDescription: String? {
        switch self {
        case .helperNotFound:        // TUN-1
            return "Freewire is missing a component it needs. Reinstalling should fix it."
        case .helperNeedsPrivileges: // TUN-2
            return "Freewire needs administrator access to create the tunnel."
        case .helperFailed(let detail): // TUN-3
            return "The tunnel could not start. \(detail)"
        case .badReadyLine:          // TUN-4
            return "The tunnel reported something unexpected. Try connecting again."
        case .timedOut:              // TUN-5
            return "The tunnel took too long to start. Try connecting again."
        case .allPathsFailed:
            // Not surfaced: doConnect routes this to CONN-2a or CONN-2b after
            // the captive portal probe.
            return "All transport paths failed."
        }
    }
}
