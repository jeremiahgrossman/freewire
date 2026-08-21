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

    init(api: ServerAPI, identity: DeviceIdentity) {
        self.api = api
        self.identity = identity
    }

    /// Certificate verification is skipped only for servers on loopback or a
    /// private network, where a self-signed development certificate is expected.
    /// Any routable host must present a valid CA-signed certificate.
    private var allowsSelfSignedCert: Bool {
        let h = api.serverHost
        if h == "localhost" || h == "::1" || h.hasPrefix("127.") { return true }
        if h.hasPrefix("10.") || h.hasPrefix("192.168.") { return true }
        // 172.16.0.0/12
        if h.hasPrefix("172.") {
            let octet = h.dropFirst(4).prefix { $0.isNumber }
            if let n = Int(octet), (16...31).contains(n) { return true }
        }
        return false
    }

    // MARK: - Public API

    func connect() async {
        // `.failed` must be allowed through: the failure panel shows a Connect
        // button, and rejecting the call left that button visibly dead.
        switch state {
        case .disconnected, .failed:
            await doConnect()
        default:
            return
        }
    }

    func cancelConnect() {
        state = .disconnected
        watchTask?.cancel(); watchTask = nil
        reconnectTask?.cancel(); reconnectTask = nil
    }

    func disconnect() async {
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

        let tmp        = FileManager.default.temporaryDirectory
        let uid        = UUID().uuidString
        let readyFile  = tmp.appendingPathComponent("fw-ready-\(uid).txt")
        let scriptFile = tmp.appendingPathComponent("fw-launch-\(uid).sh")

        // The config carries the WireGuard private key, which must never touch
        // disk. It goes to the helper over a stdin pipe; only the ready line
        // comes back through a file.
        let configData = try JSONEncoder().encode(config)
        defer { try? FileManager.default.removeItem(at: scriptFile) }

        let helperPath = helperURL.path
        let script = "#!/bin/sh\nexec '\(helperPath)' > '\(readyFile.path)' 2>&1\n"
        try script.write(to: scriptFile, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptFile.path)

        Task.detached { [scriptFile, configData] in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
            p.arguments = [scriptFile.path]
            p.standardOutput = FileHandle.nullDevice
            p.standardError  = FileHandle.nullDevice

            let stdin = Pipe()
            p.standardInput = stdin
            try? p.run()
            try? stdin.fileHandleForWriting.write(contentsOf: configData)
            try? stdin.fileHandleForWriting.close()
            p.waitUntilExit()
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
        } catch TunnelError.timedOut {
            let output = (try? String(contentsOf: readyFile, encoding: .utf8)) ?? ""
            try? FileManager.default.removeItem(at: readyFile)
            if output.contains("all_paths_failed") { throw TunnelError.allPathsFailed }
            throw TunnelError.helperFailed(output.trimmingCharacters(in: .whitespacesAndNewlines))
        } catch {
            let output = (try? String(contentsOf: readyFile, encoding: .utf8)) ?? ""
            try? FileManager.default.removeItem(at: readyFile)
            if output.contains("all_paths_failed") { throw TunnelError.allPathsFailed }
            throw TunnelError.helperFailed(output.trimmingCharacters(in: .whitespacesAndNewlines))
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
    case helperFailed(String)
    case badReadyLine(String)
    case timedOut
    case allPathsFailed

    var errorDescription: String? {
        switch self {
        case .helperNotFound:        return "Tunnel helper not found."
        case .helperFailed(let msg): return "Tunnel error: \(msg)"
        case .badReadyLine(let s):   return "Unexpected tunnel output: \(s)"
        case .timedOut:              return "Tunnel did not start within 30 seconds."
        case .allPathsFailed:        return "All transport paths failed."
        }
    }
}
