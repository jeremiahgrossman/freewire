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
            // DEBUG-1: with routing skipped nothing is protected, and the menu bar
            // icon is the signal most users act on without opening the panel, so a
            // shield there would be the same lie in a smaller space. (ESSENTIALS-1
            // is handled by AppDelegate.icon(), which reads the manager's real
            // essentialsActive flag — the pref is wrong for a one-shot offer.)
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

/// Holds the live helper's stdin write end. Thread-safe (a `let` reference set
/// from the detached launch task and closed from the main actor). Closing it
/// gives the helper EOF, which is how the tunnel is told to tear down without
/// needing sudo.
final class StdinHolder {
    private let lock = NSLock()
    private var handle: FileHandle?

    func set(_ h: FileHandle) {
        lock.lock(); defer { lock.unlock() }
        try? handle?.close() // close any previous, should not normally exist
        handle = h
    }

    func closeAndClear() {
        lock.lock(); defer { lock.unlock() }
        try? handle?.close()
        handle = nil
    }
}

@MainActor
final class TunnelManager: ObservableObject {
    @Published private(set) var state: TunnelState = .disconnected

    /// True when the current connection was built in Essentials Mode (allowlist
    /// split tunnel). The panel shows ESSENTIALS-1 ("Limited connectivity")
    /// instead of "Protected" when this is set. Reset in killTunnel.
    @Published private(set) var essentialsActive = false

    /// A one-shot Essentials Mode request from the in-flow offer (the "try
    /// messaging & email only" button on a portal block), so a user can try it on
    /// this network without turning the Settings toggle on for every network. Set
    /// by connectEssentials(); cleared on disconnect (killTunnel).
    private var tryEssentialsOnce = false

    /// Whether the LAST connect attempt was built in Essentials Mode. The in-flow
    /// offer hides itself when the failed attempt already tried essentials, so the
    /// user is not offered the same thing that just failed.
    @Published private(set) var lastAttemptUsedEssentials = false

    /// The allowlist to send the helper when Essentials Mode is on (the Settings
    /// toggle OR a one-shot in-flow request), else nil (full tunnel). Records
    /// `essentialsActive`/`lastAttemptUsedEssentials` so the panel reflects the real
    /// scope and never falsely shows "Protected."
    private func essentialsConfig() -> [String]? {
        let on = Preferences.shared.essentialsMode || tryEssentialsOnce
        essentialsActive = on
        lastAttemptUsedEssentials = on
        return on ? Preferences.shared.essentialsAllowlist : nil
    }

    /// True when the in-flow "try messaging & email only" offer is worth showing:
    /// the last attempt was NOT already essentials (else it just failed), and the
    /// Settings toggle is off (else every connect already tries it).
    var canOfferEssentials: Bool {
        !lastAttemptUsedEssentials && !Preferences.shared.essentialsMode
    }

    /// One-shot: retry the connection in Essentials Mode for this network only.
    func connectEssentials() async {
        tryEssentialsOnce = true
        await connect()
    }

    /// PRIVACY-1: true when the tunnel is up but encrypted DNS (DoH) is not, so
    /// lookups reach the network's resolver in cleartext. The tunnel still
    /// carries and encrypts traffic — only the lookups are exposed — so this
    /// drives a soft warning *below* the connected status, never a replacement
    /// for "Protected" (the same rendering rule DNS-1 follows). Published so the
    /// connected panel re-renders; cleared automatically when the helper reports
    /// DoH restored (it retries every 60s), and on teardown.
    @Published private(set) var dohLeaking: Bool = false

    /// The active tunnel's stdout file (where the helper writes "ready …" and
    /// the "doh up"/"doh down" status lines), tailed by dohMonitorTask for later
    /// DoH transitions. Removed and cleared on teardown.
    private var dohStatusFileURL: URL?
    private var dohMonitorTask: Task<Void, Never>?

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
    /// The live helper's stdin write end. Closing it signals the helper to tear
    /// down (it exits on EOF), which works even when `sudo --stop` cannot because
    /// the sudo timestamp expired. A `let` reference type so the detached launch
    /// task and the main actor can both reach it safely. See StdinHolder.
    private let tunnelStdin = StdinHolder()
    /// Where the captive portal last redirected us, for a later retry.
    private var lastPortalURL: URL?
    /// The transport that last carried traffic on this network.
    ///
    /// Reconnect used to restart the chain from the top, re-testing WireGuard,
    /// HTTP CONNECT and TLS/443 on a network that had already refused all three
    /// — spending most of the 11s fallback budget to arrive back where it
    /// started. On a portal that permits only the DNS tunnel, every recovery
    /// paid that in full, and the user is unprotected throughout.
    ///
    /// The chain still falls through to everything else if the remembered path
    /// no longer works, so a network change costs one wasted handshake budget
    /// rather than a failure.
    private var lastGoodTransport: TunnelTransport?
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
                preferredTransport: Preferences.shared.forceTransport,
                dnsResolver: Preferences.shared.dnsResolverOverride,
                dnsTunnelDomain: server.dnsTunnelDomain,
                cdnHost: server.cdnHost,
                essentialsAllowlist: essentialsConfig()
            )

            // CONN-5: the control plane answered above, so this is a normal
            // (non-captive-portal) network. The tunnel must come up inside the
            // 10s budget; a timeout is retried once automatically and then
            // surfaced as CONN-5. This is distinct from allPathsFailed, which
            // the helper reports explicitly and which propagates to CONN-2.
            var launched = try await launchTunnelTimed(config: cfg, seconds: 10)
            if launched == nil {
                await killTunnel()
                guard !Task.isCancelled else { await deregisterPeer(); return }
                launched = try await launchTunnelTimed(config: cfg, seconds: 10)
            }
            guard let (ifName, transport) = launched else {
                await killTunnel()
                await deregisterPeer()
                guard !Task.isCancelled else { return }
                state = .failed(APIError.connectionTimedOut)   // CONN-5
                return
            }
            // The user may have cancelled while the helper was starting.
            guard !Task.isCancelled else {
                await killTunnel()
                await deregisterPeer()
                return
            }
            lastGoodTransport = transport
            // Cache the control-plane state so a later connect can succeed when a
            // portal blocks fetchConfig/registerPeer. Only cached after a real
            // connection, so we never cache a config that did not work.
            CachedConnection(
                serverPublicKey: server.publicKey,
                serverEndpoint:  server.endpoint,
                tlsPort:         server.tlsEndpointPort,
                dnsTunnelPort:   server.dnsTunnelPort,
                icmpUDPPort:     server.icmpUDPPort,
                dnsTunnelDomain: server.dnsTunnelDomain,
                cdnHost: server.cdnHost,
                tunnelIP:        peer.tunnelIP,
                keepalive:       peer.keepaliveInterval,
                peerToken:       peer.peerToken
            ).save(host: api.serverHost)
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
        } catch APIError.serverUnreachable {
            // The API was unreachable, which on this product's core use case is
            // not a server outage: a captive portal blocks everything until you
            // log in, including our API, so this is the *first* thing that fails
            // on hotel and airport wifi.
            //
            // The portal probe used to run only after the transport chain had
            // exhausted every path, which requires getting past registration.
            // Registration never happened, so the probe never ran, and the user
            // was told "Freewire's servers are unreachable right now" while
            // sitting in front of a login page the app could have opened for
            // them. That is the exact situation the product exists for, and it
            // reported the one thing guaranteed not to be the cause.
            await killTunnel()
            guard !Task.isCancelled else { await deregisterPeer(); return }

            // Before deciding this is a portal to log into, try the cached
            // connection. If we have connected to this server before, the DNS
            // transport can carry the tunnel through the portal without the
            // blocked control-plane calls -- the whole point of the product.
            if let cached = CachedConnection.load(host: api.serverHost),
               let result = await connectFromCache(cached) {
                lastGoodTransport = result.transport
                peerToken = cached.peerToken
                state = .connected(
                    tunnelIP: cached.tunnelIP,
                    interfaceName: result.ifName,
                    connectedAt: Date(),
                    transport: result.transport
                )
                startNetworkMonitor()
                startWatchdog()
                startUpgradeManager(serverHost: api.serverHost, transport: result.transport)
                return
            }

            await deregisterPeer()
            guard !Task.isCancelled else { return }
            switch await probeCaptivePortal() {
            case .captivePortal(let url):
                state = .captivePortal(redirectURL: url)
            case .genuineBlock:
                // Nothing intercepting and our server unreachable. Could be a
                // hard block or a real outage; CONN-2b says the network is
                // blocking, which is the more actionable of the two and the one
                // the user can do something about.
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
        // `take()` throws TokenError.issuerKeyChanged (TRUST-4) when the issuer
        // key changed since first use; that propagates to doConnect's generic
        // catch, which surfaces it as a hard block, exactly like the TRUST-1/2/3
        // APIErrors from fetchConfig.
        try await api.registerPeer(
            publicKeyBase64: identity.publicKeyBase64,
            token: try await tokens.take()
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

            // Prefer the cached connection, exactly as the initial connect does.
            // Reconnect used to deregister the peer and re-register through the
            // API on every attempt, which (1) needs the control plane reachable --
            // and a captive portal blocks it, which is the very situation a
            // dropped tunnel reconnects into, so reconnect failed on the networks
            // it matters on -- and (2) spent a Privacy Pass token each time, so a
            // flurry of reconnects or a contended token budget failed outright
            // (caught by the regression suite). The peer is persistent, so reuse
            // it: no control-plane calls, no token, works behind a portal.
            if let cached = CachedConnection.load(host: api.serverHost),
               let result = await connectFromCache(cached) {
                lastGoodTransport = result.transport
                peerToken = cached.peerToken
                state = .connected(
                    tunnelIP: cached.tunnelIP,
                    interfaceName: result.ifName,
                    connectedAt: Date(),
                    transport: result.transport
                )
                startNetworkMonitor()
                startWatchdog()
                startUpgradeManager(serverHost: api.serverHost, transport: result.transport)
                return
            }

            // No usable cache (first-ever connect lost, or the cache is stale and
            // carried nothing): fall back to a full re-register via the API. This
            // needs the control plane, so it only works off a portal -- acceptable
            // as the last resort once the cache path has been tried.
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
                    // Try what was working before walking the whole chain again.
                    preferredTransport: Preferences.shared.forceTransport ?? lastGoodTransport?.rawValue,
                    dnsResolver: Preferences.shared.dnsResolverOverride,
                    dnsTunnelDomain: server.dnsTunnelDomain,
                    cdnHost: server.cdnHost,
                    essentialsAllowlist: essentialsConfig()
                )

                let (ifName, transport) = try await launchTunnel(config: cfg)
                lastGoodTransport = transport
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
        // When a transport is pinned for testing, don't let the upgrade manager
        // switch away from it -- otherwise a forced DNS field test would drift to
        // TLS/443 the moment a probe found it reachable.
        if Preferences.shared.forceTransport != nil { return }
        // The DNS zone for the `.dns` upgrade probe. Read from the cache, which is
        // saved before this runs on every connect path; nil is a safe fallback to
        // the helper's default zone. Only relevant when upgrading off the ICMP
        // tunnel (the sole path from which DNS is a faster target).
        let cached = CachedConnection.load(host: serverHost)
        let mgr = PathUpgradeManager(
            serverHost: serverHost,
            currentTransport: transport,
            dnsTunnelDomain: cached?.dnsTunnelDomain,
            helperURL: Self.tunnelHelperURL,
            udp443Port: cached?.tlsPort ?? 443
        )
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

        // Upgrade via the cached connection, fastest-first. A probe told us a
        // faster path is reachable; rebuild reusing the persistent peer (no
        // control-plane call, no Privacy Pass token -- same reasons as reconnect)
        // and let the fastest-first chain choose. It aims at WireGuard-direct and
        // falls through to whatever is fastest-available, so a portal-login that
        // opens the network upgrades DNS all the way to WireGuard, not just to the
        // one path the probe happened to confirm.
        //
        // `fastestFirst: true` is load-bearing: connectFromCache otherwise prefers
        // lastGoodTransport, which here is the SLOW carrier being left, so
        // orderCandidates would move it to the front and the rebuild would settle
        // right back on it -- making every upgrade a no-op. (forceTransport is nil
        // here anyway; the upgrade manager is suppressed while it is set.)
        if let cached = CachedConnection.load(host: api.serverHost),
           let result = await connectFromCache(cached, fastestFirst: true) {
            guard !Task.isCancelled else { await killTunnel(); return }
            lastGoodTransport = result.transport
            peerToken = cached.peerToken
            // connectedAt preserved: an upgrade should not reset the session clock.
            state = .connected(
                tunnelIP: cached.tunnelIP,
                interfaceName: result.ifName,
                connectedAt: at,
                transport: result.transport
            )
            startWatchdog()
            // Only resume probing if we actually moved faster; otherwise a
            // no-progress rebuild would schedule the identical upgrade forever.
            if result.transport.priority < old.priority {
                startUpgradeManager(serverHost: api.serverHost, transport: result.transport)
            }
            return
        }

        // No usable cache: fall back to a full re-register via the API (needs the
        // control plane, so only off a portal). Still fastest-first: no preferred
        // transport, so the chain reaches WireGuard-direct when available.
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
                preferredTransport: nil, // fastest-first chain, up to WireGuard-direct
                dnsResolver: Preferences.shared.dnsResolverOverride,
                dnsTunnelDomain: server.dnsTunnelDomain,
                cdnHost: server.cdnHost,
                essentialsAllowlist: essentialsConfig()
            )
            let (ifName, newTransport) = try await launchTunnel(config: cfg)

            guard !Task.isCancelled else {
                await killTunnel()
                await deregisterPeer()
                return
            }

            lastGoodTransport = newTransport
            state = .connected(
                tunnelIP: peer.tunnelIP,
                interfaceName: ifName,
                connectedAt: at,
                transport: newTransport
            )
            startWatchdog()
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
                    // The helper died without cleaning up. Since the DNS
                    // takeover points the system at a forwarder inside that
                    // process, leaving it alone means the machine has no
                    // resolver at all -- not a slow one, none. Repair before
                    // anything else, including before reconnecting.
                    await Self.restoreNetworkState()
                    self.stopUpgradeManager()
                    self.reconnectTask?.cancel()
                    self.reconnectTask = Task { await self.doReconnect(startingAt: 0) }
                    return
                }
            }
        }
    }

    /// Puts routes and resolvers back after a helper died ungracefully.
    ///
    /// Cheap and safe to call when nothing is broken: it reads the state files
    /// the helper writes and does nothing if they are absent.
    nonisolated static func restoreNetworkState() async {
        await Task.detached(priority: .userInitiated) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
            p.arguments = ["-n", TunnelManager.helperPath, "--restore"]
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            try? p.run()
            p.waitUntilExit()
        }.value
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
        // Single-user: the peer registration is persistent. The device's identity
        // is its WireGuard key (see data-model.md), and keeping it registered on
        // the server is what lets a later connect on a captive portal reuse it via
        // CachedConnection when the API is blocked. We drop only the local session
        // token here; the server keeps the peer. Re-registering the same key later
        // displaces the old entry, so this never leaks slots for the one device.
        //
        // Removing the peer on every disconnect was the multi-user, free-the-slot
        // behavior; it is deferred with the rest of multi-user (see CLAUDE.md).
        peerToken = nil
    }

    private func killTunnel() async {
        // The next connection re-derives essentials scope from its own config; a
        // stale flag here would mislabel a later full-tunnel connection as limited.
        // Clear the one-shot too: a fresh disconnect ends the "essentials on this
        // network" session, so the next manual connect starts as full tunnel.
        essentialsActive = false
        tryEssentialsOnce = false
        // Stop tailing the old tunnel's stdout and clear the PRIVACY-1 warning:
        // a torn-down tunnel is not leaking DNS, and the next launch will report
        // its own DoH state afresh.
        stopDoHMonitor()
        // Primary teardown: close the helper's stdin. It exits on EOF and runs
        // its own cleanup, with no privilege needed -- so this works even when the
        // sudo `--stop` below cannot authenticate. The `--stop` stays as a backup
        // and to wait for cleanup to finish.
        tunnelStdin.closeAndClear()
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

    // MARK: - DoH status monitor (PRIVACY-1)

    /// Tails the active tunnel's stdout file for the helper's "doh up"/"doh down"
    /// status lines and mirrors them onto `dohLeaking`.
    ///
    /// The helper writes "doh down" during routing setup (before "ready") when
    /// the DoH forwarder cannot start, and "doh up" again if its 60s background
    /// retry restores encrypted DNS — so polling this one file surfaces both the
    /// initial PRIVACY-1 state and its automatic dismissal without any second
    /// channel. A transport that cannot carry DoH at all (dns/icmp) emits neither
    /// line; that is DNS-1, warned separately, so `dohLeaking` stays false here.
    private func startDoHMonitor(readyFile: URL) {
        stopDoHMonitor()
        dohStatusFileURL = readyFile
        dohMonitorTask = Task { [weak self] in
            // Read immediately, then every few seconds. The first read picks up
            // the state the helper already wrote by the time "ready" arrived.
            while !Task.isCancelled {
                let leak = await Self.readDoHLeak(from: readyFile)
                guard let self, !Task.isCancelled else { return }
                if let leak, self.dohLeaking != leak {
                    self.dohLeaking = leak
                }
                try? await Task.sleep(nanoseconds: 5_000_000_000)
            }
        }
    }

    private func stopDoHMonitor() {
        dohMonitorTask?.cancel()
        dohMonitorTask = nil
        dohLeaking = false
        if let url = dohStatusFileURL {
            try? FileManager.default.removeItem(at: url)
            dohStatusFileURL = nil
        }
    }

    /// Reads the file off the main actor and returns the newest DoH state it
    /// carries: true for "doh down" (leaking), false for "doh up", nil if the
    /// helper has written neither line.
    nonisolated private static func readDoHLeak(from url: URL) async -> Bool? {
        await Task.detached(priority: .utility) {
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { return nil }
            return DoHStatus.latestLeak(in: text)
        }.value
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

    /// Brings the tunnel up from cached control-plane state, without any API
    /// call. Used when a portal blocks fetchConfig/registerPeer but we have
    /// connected to this server before. Returns nil if no transport carries the
    /// tunnel (e.g. the peer is no longer registered), leaving the caller to fall
    /// back to captive-portal handling.
    ///
    /// `fastestFirst` distinguishes the two callers. Reconnect (false) prefers
    /// the carrier that last carried traffic, so a café where only a late-chain
    /// carrier works does not re-walk all eight on every drop. A path upgrade
    /// (true) must NOT prefer the current carrier -- that is the slow one it is
    /// trying to leave -- so it passes no preference and runs the true
    /// fastest-first chain, climbing to the fastest the network now allows.
    private func connectFromCache(_ cached: CachedConnection, fastestFirst: Bool = false) async -> (ifName: String, transport: TunnelTransport)? {
        state = .connecting(status: "Using your saved connection for this network.")
        // Upgrade: no preference (fastest-first). Reconnect: prefer the last
        // working carrier. A pinned forceTransport always wins for field tests.
        let preferred = fastestFirst
            ? Preferences.shared.forceTransport
            : (Preferences.shared.forceTransport ?? lastGoodTransport?.rawValue)
        let cfg = TunnelConfig(
            privateKey:      identity.privateKeyBase64,
            serverPublicKey: cached.serverPublicKey,
            serverEndpoint:  cached.serverEndpoint,
            serverHost:      api.serverHost,
            tunnelIP:        cached.tunnelIP,
            serverTunnelIP:  "10.0.0.1",
            keepalive:       cached.keepalive,
            insecureTLS:     ServerTrust.trustsSelfSignedCertificate(host: api.serverHost),
            tlsPort:         cached.tlsPort,
            dnsTunnelPort:   cached.dnsTunnelPort,
            icmpUDPPort:     cached.icmpUDPPort,
            // Prefer the carrier that last carried traffic, so a café where only
            // a late-chain carrier works (cdn_wss is last) does not re-walk all
            // eight carriers on every reconnect -- ~11s each, and café wifi drops
            // often. Safe here: connectFromCache runs ONLY behind a portal (the
            // API path handles good networks), so preferring the last winner
            // cannot slow an open network onto a slower carrier. On the first
            // connect of a session lastGoodTransport is nil and the chain walks
            // normally to discover what works. During an upgrade `preferred` is
            // nil (fastest-first) so the rebuild does not settle back on the slow
            // carrier it is leaving.
            preferredTransport: preferred,
            dnsResolver:     Preferences.shared.dnsResolverOverride,
            dnsTunnelDomain: cached.dnsTunnelDomain,
            cdnHost: cached.cdnHost,
            essentialsAllowlist: essentialsConfig()
        )
        guard let (ifName, transport) = try? await launchTunnel(config: cfg), !Task.isCancelled else {
            await killTunnel()
            return nil
        }
        return (ifName, transport)
    }

    /// Launches the tunnel with an open-network time budget (CONN-5).
    ///
    /// Returns the launched interface/transport, or nil if the launch did not
    /// finish within `seconds`. A thrown failure -- `allPathsFailed`, a helper
    /// error -- propagates unchanged, so only a genuine timeout returns nil; the
    /// caller retries a nil once and then surfaces CONN-5. The launch that timed
    /// out keeps running detached (its sudo helper watches stdin), so the caller
    /// must `killTunnel()` before retrying or giving up.
    private func launchTunnelTimed(config: TunnelConfig, seconds: Double) async throws -> (String, TunnelTransport)? {
        try await withThrowingTaskGroup(of: Optional<(String, TunnelTransport)>.self) { group in
            group.addTask { try await self.launchTunnel(config: config) }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return nil   // timer won the race
            }
            // First branch to finish decides it: the launch's value/throw, or the
            // timer's nil. Cancel the loser either way.
            let outcome = try await group.next() ?? nil
            group.cancelAll()
            return outcome
        }
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
        // Tee the helper's stderr (the transport-chain diagnostics) to a file, so
        // it survives every outcome -- success, failure, and the captive-portal
        // branch -- and can be read after the fact:
        //   cat /tmp/freewire-tunnel-stderr.log
        // The old pipe was only drained on the failure path and only its buffered
        // tail, so the dns/tls reasons were lost exactly when they mattered.
        let stderrLogURL = URL(fileURLWithPath: "/tmp/freewire-tunnel-stderr.log")
        FileManager.default.createFile(atPath: stderrLogURL.path, contents: nil)
        let stderrLog = try? FileHandle(forWritingTo: stderrLogURL)
        let skipRouting = Preferences.shared.skipRouting

        Task.detached { [helperPath, configData, readyFile, stderrLog, skipRouting, tunnelStdin] in
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
            p.standardError = stderrLog ?? FileHandle.nullDevice

            let stdin = Pipe()
            p.standardInput = stdin
            try? p.run()
            try? stdin.fileHandleForWriting.write(contentsOf: configData)
            // Keep the write end OPEN. The helper watches its stdin and tears
            // itself down on EOF, so closing this handle (on disconnect) or the
            // app dying is what reliably stops the tunnel -- unlike `sudo --stop`,
            // which fails silently once the sudo timestamp expires. Held so
            // killTunnel can close it; closes automatically if the app dies.
            tunnelStdin.set(stdin.fileHandleForWriting)
            p.waitUntilExit()
            try? stderrLog?.close()
        }

        func failure() -> TunnelError {
            let out = (try? String(contentsOf: readyFile, encoding: .utf8)) ?? ""
            let err = (try? String(contentsOf: stderrLogURL, encoding: .utf8)) ?? ""
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

            // Line format: "ready <ifName> <tunnelIP> <transport>"
            let parts = readyLine.split(separator: " ")
            guard parts.count >= 2, parts[0] == "ready", !parts[1].isEmpty else {
                try? FileManager.default.removeItem(at: readyFile)
                throw TunnelError.badReadyLine(readyLine)
            }
            let ifName = String(parts[1])
            let transport = parts.count >= 4
                ? TunnelTransport(rawValue: String(parts[3])) ?? .wireguard
                : .wireguard
            // Keep the stdout file and tail it for PRIVACY-1: the helper writes
            // "doh down"/"doh up" on this same channel, before "ready" for the
            // initial state and again if a background retry restores DoH. The
            // monitor owns the file's lifetime now and removes it on teardown.
            startDoHMonitor(readyFile: readyFile)
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
    let dnsTunnelDomain:    String?
    let cdnHost:            String?
    // Essentials Mode allowlist; nil = full tunnel. Client-assembled, never from
    // the server's /v1/config, so the server can't force reduced scope.
    let essentialsAllowlist: [String]?

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
        case dnsTunnelDomain    = "dns_tunnel_domain"
        case cdnHost            = "cdn_host"
        case essentialsAllowlist = "essentials_allowlist"
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
