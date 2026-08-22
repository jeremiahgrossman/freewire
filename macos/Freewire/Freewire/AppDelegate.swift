import Cocoa
import SwiftUI
import Combine

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private var clickMonitor: Any?
    private var tunnelManager: TunnelManager?
    private var cancellable: AnyCancellable?
    private let api = ServerAPI(host: "3.88.155.229")

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

    deinit {
        // NSEvent global monitors are not tied to the observer's lifetime and
        // must be removed explicitly.
        if let m = clickMonitor { NSEvent.removeMonitor(m) }
    }

    func applicationWillTerminate(_ notification: Notification) {
        // Signal the tunnel, then wait for it to actually go.
        //
        // waitUntilExit() here waits for *pkill*, not for the tunnel to handle
        // SIGTERM and run its routing cleanup. The app could exit first, so the
        // tunnel's routes outlived it. That matters less since the tunnel stopped
        // replacing the default route -- its routes now die with the interface --
        // but waiting is still what makes cleanup deterministic rather than a race.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        p.arguments = ["-n", "/usr/bin/pkill", "-x", "freewire-tunnel"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError  = FileHandle.nullDevice
        try? p.run()
        p.waitUntilExit()

        // Poll for the process to disappear, bounded so quit is never blocked
        // for long by a tunnel that will not die.
        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline {
            let check = Process()
            check.executableURL = URL(fileURLWithPath: "/usr/bin/pgrep")
            check.arguments = ["-x", "freewire-tunnel"]
            check.standardOutput = FileHandle.nullDevice
            check.standardError  = FileHandle.nullDevice
            try? check.run()
            check.waitUntilExit()
            if check.terminationStatus != 0 { break } // no match: it is gone
            Thread.sleep(forTimeInterval: 0.1)
        }

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
        case .awaitingPortalAuth:       return "Freewire — Waiting for network sign-in"
        case .noNetwork:                return "Freewire — No internet connection"
        case .failed(let error):
            // Saying only "Not connected" hid the reason at the one moment the
            // user is hovering to find out what went wrong.
            return "Freewire — \(error.localizedDescription)"
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
