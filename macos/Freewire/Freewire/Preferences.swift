import Foundation
import ServiceManagement

@MainActor
final class Preferences {
    static let shared = Preferences()

    private enum Key {
        static let killSwitch = "killSwitch"
        static let autoConnect = "autoConnect"
        static let networkIntelligence = "networkIntelligence"
        static let initialized = "prefsInitialized"
        static let onboardingDone = "onboardingDone"
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
        UserDefaults.standard.set(true, forKey: Key.killSwitch)
        UserDefaults.standard.set(true, forKey: Key.autoConnect)
        UserDefaults.standard.set(false, forKey: Key.networkIntelligence)
        UserDefaults.standard.set(true, forKey: Key.initialized)
    }
}
