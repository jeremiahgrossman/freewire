import Cocoa
import SwiftUI
import Combine

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private var clickMonitor: Any?
    private var tunnelManager: TunnelManager?
    private var cancellable: AnyCancellable?
    private let api = ServerAPI(host: "192.168.97.2")

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)

        let identity: DeviceIdentity
        do {
            identity = try DeviceIdentity()
        } catch {
            showFatalError("Keychain error", detail: error.localizedDescription)
            return
        }

        let mgr = TunnelManager(api: api, identity: identity)
        tunnelManager = mgr

        setupStatusItem(mgr: mgr)

        if !Preferences.shared.hasCompletedOnboarding {
            // First launch: show onboarding window instead of auto-connecting.
            OnboardingWindowController.show(tunnelManager: mgr)
        } else if Preferences.shared.autoConnect {
            Task { await mgr.connect() }
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Kill tunnel process synchronously so routing is cleaned up before exit.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        p.arguments = ["/usr/bin/pkill", "-x", "freewire-tunnel"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError  = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()

        // Free the server slot immediately. Reads the token from its lock-guarded
        // box and issues the DELETE directly: hopping to the main actor here would
        // deadlock, since this handler already owns the main thread.
        if let token = tunnelManager?.peerTokenBox.token {
            api.removePeerBlocking(token: token)
        }
    }

    // MARK: - Status item + popover

    private func setupStatusItem(mgr: TunnelManager) {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem = item

        if let btn = item.button {
            btn.image   = icon(for: mgr.state)
            btn.toolTip = tooltip(for: mgr.state)
            btn.action  = #selector(togglePanel)
            btn.target  = self
        }

        let pop = NSPopover()
        pop.contentSize  = NSSize(width: 240, height: 300)
        pop.behavior     = .transient
        pop.contentViewController = NSHostingController(
            rootView: PanelView(
                tunnelManager: mgr,
                onPreferences: { [weak self] in self?.openPreferences() },
                onQuit:        { NSApp.terminate(nil) }
            )
        )
        popover = pop

        // Dismiss popover on outside click.
        // AppKit calls this handler on the main thread, but Swift 6 doesn't know that —
        // wrap in Task { @MainActor } so the compiler can verify @MainActor access.
        clickMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) { [weak self] _ in
            Task { @MainActor [weak self] in self?.closePanel() }
        }

        // objectWillChange fires before @Published updates. Task { @MainActor } defers until
        // after the current actor turn, so by the time it runs the state is already updated.
        // Wrapping in Task { @MainActor } is required in Swift 6 — a plain sink closure
        // is not @MainActor-isolated even when delivered on the main thread.
        cancellable = mgr.objectWillChange
            .sink { [weak self, weak mgr] in
                Task { @MainActor [weak self, weak mgr] in
                    guard let self, let mgr else { return }
                    self.statusItem?.button?.image   = self.icon(for: mgr.state)
                    self.statusItem?.button?.toolTip = self.tooltip(for: mgr.state)
                }
            }
    }

    @objc private func togglePanel() {
        guard let btn = statusItem?.button, let pop = popover else { return }
        if pop.isShown {
            closePanel()
        } else {
            pop.show(relativeTo: btn.bounds, of: btn, preferredEdge: .minY)
            pop.contentViewController?.view.window?.becomeKey()
        }
    }

    private func closePanel() {
        popover?.performClose(nil)
    }

    private func icon(for state: TunnelState) -> NSImage? {
        let img = NSImage(systemSymbolName: state.iconSymbol, accessibilityDescription: "Freewire")
        img?.isTemplate = true
        return img
    }

    private func tooltip(for state: TunnelState) -> String {
        switch state {
        case .disconnected:             return "Freewire — Not connected"
        case .connecting:               return "Freewire — Connecting..."
        case .connected:                return "Freewire — Protected"
        case .reconnecting:             return "Freewire — Reconnecting... Traffic not protected"
        case .blocked:                  return "Freewire — Connection lost. Click to reconnect."
        case .captivePortal:            return "Freewire — Network login required"
        case .networkBlock:             return "Freewire — Network is blocking VPN"
        case .failed:                   return "Freewire — Not connected"
        }
    }

    // MARK: - Preferences

    private func openPreferences() {
        closePanel()
        PreferencesWindowController.shared.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    // MARK: - Error handling

    private func showFatalError(_ title: String, detail: String) {
        let alert = NSAlert()
        alert.messageText     = title
        alert.informativeText = detail
        alert.alertStyle      = .critical
        alert.runModal()
        NSApp.terminate(nil)
    }
}
