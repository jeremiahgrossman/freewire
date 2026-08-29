import Foundation
import ServiceManagement

@MainActor
final class Preferences {
    static let shared = Preferences()

    private enum Key {
        static let killSwitch = "killSwitch"
        static let dnsResolverOverride = "dnsResolverOverride"
        static let forceTransport = "forceTransport"
        static let skipRouting = "skipRouting"
        static let pinnedServerKey = "pinnedServerKey"
        static let autoConnect = "autoConnect"
        static let networkIntelligence = "networkIntelligence"
        static let essentialsMode = "essentialsMode"
        static let essentialsAllowlist = "essentialsAllowlist"
        static let initialized = "prefsInitialized"
        static let onboardingDone = "onboardingDone"
    }

    /// Essentials Mode: on a network so restrictive that only a slow carrier
    /// escapes, carry ONLY the allowlist (messaging/email/push) and blackhole the
    /// rest, instead of a full tunnel that collapses under the throttle. Opt-in and
    /// off by default -- it reduces what is protected, so the user must choose it.
    /// See ESSENTIALS-MODE-SPEC.md and error-states-spec.md (ESSENTIALS-1).
    var essentialsMode: Bool {
        get { UserDefaults.standard.bool(forKey: Key.essentialsMode) }
        set { UserDefaults.standard.set(newValue, forKey: Key.essentialsMode) }
    }

    /// Destination allowlist for Essentials Mode: the CIDRs/IPs routed into the
    /// tunnel while everything else stays on the physical path. Defaults to Apple's
    /// 17.0.0.0/8 (push + iMessage, needs no DNS). Sent to the helper as
    /// `essentials_allowlist`; empty falls back to the default rather than
    /// tunnelling nothing.
    var essentialsAllowlist: [String] {
        get {
            let v = UserDefaults.standard.stringArray(forKey: Key.essentialsAllowlist) ?? []
            let cleaned = v.map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
            return cleaned.isEmpty ? ["17.0.0.0/8"] : cleaned
        }
        set { UserDefaults.standard.set(newValue, forKey: Key.essentialsAllowlist) }
    }

    /// Resolver the DNS tunnel should query instead of the system one.
    ///
    /// Testing aid: the tunnel zone is only delegated in production, so against
    /// a development server the system resolver cannot reach it. No UI sets
    /// this; it is written with
    /// `defaults write com.freewire.vpn.Freewire dnsResolverOverride <ip>`.
    var dnsResolverOverride: String? {
        let v = UserDefaults.standard.string(forKey: Key.dnsResolverOverride)
        return (v?.isEmpty ?? true) ? nil : v
    }

    /// Pins the fallback chain to one transport for a connect, via the tunnel's
    /// preferred_transport (tried first; on success the others are skipped).
    ///
    /// Testing aid, no UI. A field test's main question -- does this portal let
    /// Freewire online -- is answered whichever transport wins, but validating a
    /// specific path (e.g. the DNS server-direct carrier) needs that path to be
    /// the one selected, and a portal that allows HTTPS would otherwise settle on
    /// TLS/443 and never exercise DNS. Set with
    /// `defaults write com.freewire.vpn.Freewire forceTransport dns` (values:
    /// wireguard, http_connect, tls443, wss443, dns, icmp_udp); clear with `delete` to
    /// restore normal selection.
    var forceTransport: String? {
        let v = UserDefaults.standard.string(forKey: Key.forceTransport)
        return (v?.isEmpty ?? true) ? nil : v
    }

    /// Runs the tunnel without taking over routing.
    ///
    /// Debug builds only. For environments whose egress cannot carry the tunnel
    /// -- container runtimes on macOS drop forwarded traffic -- where the point
    /// of the run is which transport gets chosen. Never reachable in a release
    /// build, so no shipped client can be talked out of routing its traffic.
    var skipRouting: Bool {
        #if DEBUG
        return UserDefaults.standard.bool(forKey: Key.skipRouting)
        #else
        return false
        #endif
    }

    /// WireGuard public key the user supplied for a self-hosted server.
    ///
    /// Not a secret, so UserDefaults is appropriate; what matters is that the
    /// user chose it rather than the network supplying it.
    var pinnedServerKey: String? {
        get {
            let v = UserDefaults.standard.string(forKey: Key.pinnedServerKey)
            return (v?.isEmpty ?? true) ? nil : v
        }
        set { UserDefaults.standard.set(newValue, forKey: Key.pinnedServerKey) }
    }

    var killSwitchEnabled: Bool {
        get { UserDefaults.standard.bool(forKey: Key.killSwitch) }
        set { UserDefaults.standard.set(newValue, forKey: Key.killSwitch) }
    }

    var autoConnect: Bool {
        get { UserDefaults.standard.bool(forKey: Key.autoConnect) }
        set { UserDefaults.standard.set(newValue, forKey: Key.autoConnect) }
    }

    var networkIntelligenceEnabled: Bool {
        get { UserDefaults.standard.bool(forKey: Key.networkIntelligence) }
        set { UserDefaults.standard.set(newValue, forKey: Key.networkIntelligence) }
    }

    var hasCompletedOnboarding: Bool {
        get { UserDefaults.standard.bool(forKey: Key.onboardingDone) }
        set { UserDefaults.standard.set(newValue, forKey: Key.onboardingDone) }
    }

    var launchAtLogin: Bool {
        get { SMAppService.mainApp.status == .enabled }
        set {
            do {
                if newValue { try SMAppService.mainApp.register() }
                else { try SMAppService.mainApp.unregister() }
            } catch {
                // Non-fatal — user can retry
            }
        }
    }

    private init() {
        guard !UserDefaults.standard.bool(forKey: Key.initialized) else { return }
        // Off until FreewireHelper enforces it — a stored `true` would imply a
        // protection the app cannot deliver.
        UserDefaults.standard.set(false, forKey: Key.killSwitch)
        UserDefaults.standard.set(true, forKey: Key.autoConnect)
        UserDefaults.standard.set(false, forKey: Key.networkIntelligence)
        UserDefaults.standard.set(true, forKey: Key.initialized)
    }
}
