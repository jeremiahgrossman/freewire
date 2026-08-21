import Foundation
import ServiceManagement

@MainActor
final class Preferences {
    static let shared = Preferences()

    private enum Key {
        static let killSwitch = "killSwitch"
        static let dnsResolverOverride = "dnsResolverOverride"
        static let autoConnect = "autoConnect"
        static let networkIntelligence = "networkIntelligence"
        static let initialized = "prefsInitialized"
        static let onboardingDone = "onboardingDone"
    }

    /// Resolver the DNS tunnel should query instead of the system one.
    ///
    /// Testing aid: the tunnel zone is only delegated in production, so against
    /// a development server the system resolver cannot reach it. No UI sets
    /// this; it is written with `defaults write com.freewire.Freewire
    /// dnsResolverOverride <ip>`.
    var dnsResolverOverride: String? {
        let v = UserDefaults.standard.string(forKey: Key.dnsResolverOverride)
        return (v?.isEmpty ?? true) ? nil : v
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
