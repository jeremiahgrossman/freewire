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
    case awaitingPortalAuth(timedOut: Bool) // CONN-2a: waiting out the sign-in
    case noNetwork                    // CONN-1: no connectivity at all
    case networkBlock                 // CONN-2b: hard block, no portal
    case upgrading                    // UPGRADE-1: rebuilding on a faster path
    case failed(Error)

    /// Whether a connect attempt may start from this state.
    ///
    /// Every state listed here shows the user a button that starts one. The
    /// guard used to admit only `.disconnected` and `.failed`, so the "Try
    /// again" button on CONN-1, CONN-2a and CONN-2b called `connect()`, which
    /// returned immediately and did nothing. A user whose network dropped had
    /// no way back except quitting the app -- the button was there, it just
    /// silently did nothing, which is worse than not offering one.
    var allowsConnectAttempt: Bool {
        switch self {
        case .disconnected, .failed, .noNetwork, .networkBlock,
             .captivePortal, .awaitingPortalAuth:
            return true
        case .connecting, .connected, .reconnecting, .blocked, .upgrading:
            return false
        }
    }

    var iconSymbol: String {
        switch self {
        case .disconnected, .failed:   return "network"
        case .awaitingPortalAuth:      return "wifi.exclamationmark"
        case .noNetwork:               return "network.slash"
        case .connecting, .upgrading:  return "network.badge.shield.half.filled"
        case .connected:
            // DEBUG-1: with routing skipped nothing is protected, and the menu
            // bar icon is the signal most users act on without opening the
            // panel. A shield there would be the same lie in a smaller space.
            return UserDefaults.standard.bool(forKey: "skipRouting")
                ? "exclamationmark.triangle.fill"
                : "checkmark.shield.fill"
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
    /// The path upgrade in flight, held so disconnect can stop it.
    ///
    /// It used to run as an untracked `Task`, so disconnecting mid-upgrade left
    /// it running: it would finish registering a peer and launch a tunnel after
    /// the user had asked for none, leaving a live tunnel behind a panel that
    /// said "Not protected".
    private var upgradeTask: Task<Void, Never>?
    /// Where the captive portal last redirected us, for a later retry.
    private var lastPortalURL: URL?
    private lazy var tokens = TokenStore(
        serverBase: "https://\(api.serverHost):8080",
        // Same rule the URLSession delegate applies: a self-signed certificate
        // is acceptable exactly when the user has pinned a key, because the pin
        // rather than the certificate is what establishes trust. Gating this on
        // the address instead left the helper doing strict validation against a
        // server the rest of the client had already accepted.
        allowSelfSigned: ServerTrust.trustsSelfSignedCertificate(host: api.serverHost)
    )

    init(api: ServerAPI, identity: DeviceIdentity) {
        self.api = api
        self.identity = identity
    }


    // MARK: - Public API

    func connect() async {
        guard state.allowsConnectAttempt else { return }
        await startConnect()
    }

    /// Starts a connect attempt, tracked so Cancel can stop it.
    ///
    /// Every path that begins a connection goes through here. The portal
    /// watcher and the CONN-2b retry used to call `doConnect()` directly, which
    /// left `connectTask` nil: Cancel had nothing to cancel, so it set the state
    /// to disconnected and the still-running attempt overwrote it seconds later
    /// with connected or failed. One funnel means a future caller cannot
    /// reintroduce that by forgetting.
    private func startConnect() async {
        connectTask?.cancel()
        let task = Task { await doConnect() }
        connectTask = task
        await task.value
    }

    func cancelConnect() {
        connectTask?.cancel(); connectTask = nil
        cancelTasks()
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
        await startConnect()
    }

    // Opens the captive portal URL in the default browser so the user can authenticate.
    // Resets to disconnected so they can press Connect again after logging in.
    func openCaptivePortal(url: URL?) {
        // Remember where the portal actually sent us. "Try again" after the
        // wait lapsed reopened Apple's probe page instead, because the captured
        // redirect was never stored -- so the user was handed a generic
        // connectivity check rather than the sign-in form they were part way
        // through, and any session the portal had established was lost.
        if let url { lastPortalURL = url }
        let target = url ?? lastPortalURL ?? URL(string: "http://captive.apple.com")!
        NSWorkspace.shared.open(target)

        // Stay in a state that matches what the CONN-2a copy just promised.
        // Dropping to .disconnected here contradicted the sentence the user had
        // just read and hid the fact that Freewire was still watching.
        state = .awaitingPortalAuth(timedOut: false)

        awaitPortalTask?.cancel()
        awaitPortalTask = Task { [weak self] in
            // Portals routinely involve a payment form, an SMS code, or a
            // room-number lookup. The wait is generous, and when it does lapse
            // it says so rather than expiring silently.
            for _ in 0..<100 {   // ~5 minutes at 3s intervals
                try? await Task.sleep(nanoseconds: 3_000_000_000)
                guard let self, !Task.isCancelled else { return }
                guard case .awaitingPortalAuth = self.state else { return }
                if case .genuineBlock = await probeCaptivePortal() {
                    // No portal intercept any more: the login went through.
                    // Through startConnect so Cancel can stop the attempt this
                    // begins; calling doConnect directly left it untracked.
                    await self.startConnect()
                    return
                }
            }
            guard let self, !Task.isCancelled else { return }
            guard case .awaitingPortalAuth = self.state else { return }
            self.state = .awaitingPortalAuth(timedOut: true)
        }
    }

    /// Re-enters the portal wait after it lapsed, rather than failing outright.
    func retryPortalWait() {
        guard case .awaitingPortalAuth = state else { return }
        openCaptivePortal(url: nil)
    }

    // MARK: - Connect

    private func doConnect() async {
        // CONN-1. Without this an offline user is told "Freewire's servers are
        // unreachable right now", which points them at the wrong problem.
        if await !NetworkMonitor.hasNetwork() {
            state = .noNetwork
            startNetworkMonitor()
            return
        }

        state = .connecting(status: "Finding the best path for this network.")

        do {
            let server = try await api.fetchConfig()

            guard server.capacityAvailable else {
                throw APIError.serverAtCapacity
            }

            // Spend a token when the server issues them. A nil token means a
            // self-hosted server or a failed issuance; registering without one
            // lets the server decide rather than refusing to connect over a
            // rate-limiting mechanism.
            let peer = try await registerPeer()
            peerToken = peer.peerToken

            let cfg = TunnelConfig(
                privateKey:      identity.privateKeyBase64,
                serverPublicKey: server.publicKey,
                serverEndpoint:  server.endpoint,
                serverHost:      api.serverHost,
                tunnelIP:        peer.tunnelIP,
                serverTunnelIP:  "10.0.0.1",
                keepalive:       peer.keepaliveInterval,
                insecureTLS:     ServerTrust.trustsSelfSignedCertificate(host: api.serverHost),
                tlsPort:         server.tlsEndpointPort,
                dnsTunnelPort:   server.dnsTunnelPort,
                icmpUDPPort:     server.icmpUDPPort,
                preferredTransport: nil,
                dnsResolver: Preferences.shared.dnsResolverOverride
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
            // Kill the helper as well as releasing the peer. launchTunnel can
            // fail after the helper is already running -- a routing error, a
            // ready line that never arrives -- and only the peer was being
            // cleaned up, so the process was left holding routes and DNS with
            // nothing tracking it and the panel showing a failure.
            await killTunnel()
            await deregisterPeer()
            guard !Task.isCancelled else { return }
            state = .failed(error)
        }
    }

    /// Registers a peer, spending a token when the server issues them.
    ///
    /// Every registration goes through here. Reconnect and path upgrade used to
    /// call the API directly and passed no token, so against a token-issuing
    /// server they returned 402 on every attempt: the client could connect once
    /// and then never recover from a network change, a watchdog trip, or an
    /// upgrade. One funnel means a future path cannot forget again.
    private func registerPeer() async throws -> RegisteredPeer {
        try await api.registerPeer(
            publicKeyBase64: identity.publicKeyBase64,
            token: await tokens.take()
        )
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
                let peer  = try await registerPeer()
                peerToken = peer.peerToken

                let cfg = TunnelConfig(
                    privateKey:      identity.privateKeyBase64,
                    serverPublicKey: server.publicKey,
                    serverEndpoint:  server.endpoint,
                    serverHost:      api.serverHost,
                    tunnelIP:        peer.tunnelIP,
                    serverTunnelIP:  "10.0.0.1",
                    keepalive:       peer.keepaliveInterval,
                    insecureTLS:     ServerTrust.trustsSelfSignedCertificate(host: api.serverHost),
                    tlsPort:         server.tlsEndpointPort,
                    dnsTunnelPort:   server.dnsTunnelPort,
                    icmpUDPPort:     server.icmpUDPPort,
                    preferredTransport: nil,
                    dnsResolver: Preferences.shared.dnsResolverOverride
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
            self.upgradeTask?.cancel()
            self.upgradeTask = Task { await self.performPathUpgrade(to: faster) }
        }
        upgradeManager = mgr
        mgr.start()
    }

    private func stopUpgradeManager() {
        upgradeManager?.stop()
        upgradeManager = nil
    }

    private func performPathUpgrade(to transport: TunnelTransport) async {
        guard case .connected(_, _, let at, let old) = state,
              transport.priority < old.priority else { return }
        upgradeManager?.stop()
        // The watchdog polls for the tunnel process. During an upgrade the
        // process is deliberately absent, and a watchdog firing in that window
        // would start a reconnect that races this upgrade.
        watchTask?.cancel(); watchTask = nil

        // UPGRADE-1. From here until the new tunnel is up there is no tunnel at
        // all: the helper has exited, the routes are gone, and traffic is on the
        // normal path. Leaving the state at .connected kept the panel showing
        // "Protected" across that window -- the same defect as DEBUG-1, and
        // worse here because it happens during ordinary successful operation.
        state = .upgrading

        await killTunnel()
        await deregisterPeer()

        do {
            guard !Task.isCancelled else { return }
            let server = try await api.fetchConfig()
            let peer  = try await registerPeer()
            peerToken = peer.peerToken

            let cfg = TunnelConfig(
                privateKey:      identity.privateKeyBase64,
                serverPublicKey: server.publicKey,
                serverEndpoint:  server.endpoint,
                serverHost:      api.serverHost,
                tunnelIP:        peer.tunnelIP,
                serverTunnelIP:  "10.0.0.1",
                keepalive:       peer.keepaliveInterval,
                insecureTLS:     ServerTrust.trustsSelfSignedCertificate(host: api.serverHost),
                tlsPort:         server.tlsEndpointPort,
                dnsTunnelPort:   server.dnsTunnelPort,
                icmpUDPPort:     server.icmpUDPPort,
                // Name the path we are upgrading to. Without this the relaunched
                // tunnel restarts the chain from the top and reselects whatever
                // it had before, so the upgrade rebuilt the same tunnel and then
                // upgraded again, forever.
                preferredTransport: transport.rawValue,
                dnsResolver: Preferences.shared.dnsResolverOverride
            )
            let (ifName, newTransport) = try await launchTunnel(config: cfg)

            // A disconnect during the rebuild must not be undone by it. Without
            // this the upgrade finished, set .connected and left a live tunnel
            // running behind a panel that said "Not protected".
            guard !Task.isCancelled else {
                await killTunnel()
                await deregisterPeer()
                return
            }

            // UX-003: the server issued a fresh address during re-registration.
            // Reporting the old one left the panel showing an address the tunnel
            // no longer used. connectedAt is deliberately preserved: an upgrade
            // should not reset the session clock.
            state = .connected(
                tunnelIP: peer.tunnelIP,
                interfaceName: ifName,
                connectedAt: at,
                transport: newTransport
            )
            startWatchdog()

            // Only resume probing if the upgrade actually moved us. If the chain
            // handed back the same path -- or a slower one -- restarting the
            // manager on it would schedule the identical upgrade again.
            if newTransport.priority < old.priority {
                startUpgradeManager(serverHost: api.serverHost, transport: newTransport)
            }
        } catch {
            guard !Task.isCancelled else { return }
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
            switch self.state {
            case .reconnecting:
                self.reconnectTask?.cancel()
                self.reconnectTask = Task { await self.doReconnect(startingAt: 0) }
            case .noNetwork:
                // CONN-1 resumes on its own once connectivity returns. The
                // state is cleared first: connect() only proceeds from
                // .disconnected or .failed, so calling it from .noNetwork
                // returned immediately and the recovery never happened.
                self.state = .disconnected
                Task { await self.connect() }
            default:
                break
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
        upgradeTask?.cancel();     upgradeTask = nil
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
            // -n so a missing sudo rule fails immediately instead of blocking
            // on a password prompt nobody can answer. `--stop` returns only
            // once the tunnel has restored routes, resolvers and IPv6, so
            // waiting here waits for the cleanup rather than for a signal to
            // be delivered.
            p.arguments = ["-n", TunnelManager.helperPath, "--stop"]
            p.standardOutput = FileHandle.nullDevice
            p.standardError  = FileHandle.nullDevice
            try? p.run()
            p.waitUntilExit()
        }.value
        try? await Task.sleep(nanoseconds: 300_000_000)
    }

    // MARK: - Tunnel launch

    /// Path to the tunnel helper, shared with the termination handler.
    ///
    /// `nonisolated` because both callers need it off the main actor: the
    /// termination handler cannot await a main-actor property, and killTunnel
    /// runs on a detached task. The value depends only on the bundle layout and
    /// the filesystem, so there is no actor state to protect.
    nonisolated static var helperPath: String { tunnelHelperURL?.path ?? "" }

    nonisolated static var tunnelHelperURL: URL? {
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
        guard let helperURL = Self.tunnelHelperURL else {
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
        let skipRouting = Preferences.shared.skipRouting

        Task.detached { [helperPath, configData, readyFile, stderrPipe, skipRouting] in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
            // -n: never prompt. Without it sudo blocks on a password nobody can
            // type, the helper never starts, and the failure surfaces as an
            // empty error string.
            var args = ["-n", helperPath]
            if skipRouting {
                args.append("--skip-egress-check")
            }
            p.arguments = args

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
    let preferredTransport: String?
    let dnsResolver:        String?

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
        case preferredTransport = "preferred_transport"
        case dnsResolver        = "dns_resolver"
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
