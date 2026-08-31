import Cocoa
import SwiftUI
import Combine

// @MainActor: this is the app's UI delegate — every method runs on the main
// thread, and its helpers read TunnelManager's @MainActor-isolated state
// (`state`, `essentialsActive`). Without the annotation those reads compile as
// a warning under the developer's newer Xcode but a hard error under the CI
// runner's Xcode 16 (stricter Swift-5 actor-isolation), which broke the archive.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem?
    private var popover: NSPopover?
    private var panelHost: NSHostingController<PanelView>?
    private var clickMonitor: Any?
    private var tunnelManager: TunnelManager?
    private var cancellable: AnyCancellable?
    private let api = ServerAPI(host: "52.203.246.145")

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
        // `--stop` waits for the tunnel to finish its cleanup before returning,
        // so waiting on this process waits on the thing that matters. The
        // previous `sudo pkill` returned as soon as the signal was delivered,
        // which made cleanup a race the app could lose by exiting first.
        //
        // It also removes the passwordless sudo rule that pkill required. That
        // rule let anything running as this user kill any process on the
        // machine as root, to solve a problem belonging to one binary.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
        p.arguments = ["-n", TunnelManager.helperPath, "--stop"]
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

        // Single-user: the peer registration is persistent (see deregisterPeer /
        // data-model.md). We do NOT delete it on quit, so the next launch can
        // reconnect through a captive portal using the cached registration.
        // Freeing the slot on quit was multi-user behavior, deferred with the
        // rest of multi-user.
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
        // Width matches PanelView.width -- host.sizingOptions below makes the
        // view's own width win at runtime, but this initial value should not
        // silently disagree with it.
        pop.contentSize  = NSSize(width: PanelView.width, height: 340)
        pop.behavior     = .transient
        let host = NSHostingController(
            rootView: PanelView(
                tunnelManager: mgr,
                onQuit:        { NSApp.terminate(nil) }
            )
        )
        // Let the popover size itself to the SwiftUI content, so the larger fonts
        // and the taller error/portal states are never clipped by a fixed height.
        host.sizingOptions = [.preferredContentSize]
        pop.contentViewController = host
        popover = pop
        panelHost = host

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
            // Rebuild the root view fresh on every show, not just once at
            // startup. PanelView owns its own `screen` (.main/.settings/
            // .privacy) as @State; reusing one long-lived instance let a
            // reopen land back on Settings or Privacy instead of the main
            // status screen. A fresh PanelView always starts on .main.
            if let mgr = tunnelManager {
                panelHost?.rootView = PanelView(
                    tunnelManager: mgr,
                    onQuit:        { NSApp.terminate(nil) }
                )
            }
            // Activate first. An accessory (LSUIElement) app is often inactive
            // when its status item is clicked, and showing a popover from an
            // inactive app is where AppKit has been seen to place it against the
            // wrong screen/space rather than under the button.
            NSApp.activate(ignoringOtherApps: true)
            pop.show(relativeTo: btn.bounds, of: btn, preferredEdge: .minY)
            pop.contentViewController?.view.window?.becomeKey()
        }
    }

    private func closePanel() {
        popover?.performClose(nil)
    }

    private func icon(for state: TunnelState) -> NSImage? {
        // state.iconSymbol reads the essentialsMode PREF for the connected shield,
        // which is wrong for a one-shot in-flow offer (essentialsActive without the
        // pref). Override here, where the manager's real flag is reachable, so the
        // icon matches the tooltip and panel: no shield when scope is limited.
        var symbol = state.iconSymbol
        if case .connected = state, tunnelManager?.essentialsActive == true {
            symbol = "exclamationmark.triangle.fill"
        }
        let img = NSImage(systemSymbolName: symbol, accessibilityDescription: "Freewire")
        img?.isTemplate = true
        return img
    }

    private func tooltip(for state: TunnelState) -> String {
        switch state {
        case .disconnected:             return "Freewire — Not connected"
        case .connecting:               return "Freewire — Connecting..."
        case .connected:
            // Matches the panel's headline. The tooltip is what the user sees
            // without opening anything, so a shield claim here would be the same
            // lie the panel no longer tells (ESSENTIALS-1 and DEBUG-1 both replace
            // "Protected" because most / all traffic is not protected).
            if tunnelManager?.essentialsActive == true {
                return "Freewire — Limited connectivity (messaging & email only)"
            }
            return UserDefaults.standard.bool(forKey: "skipRouting")
                ? "Freewire — Debug mode: routing off. Traffic is NOT protected."
                : "Freewire — Protected"
        case .upgrading:                return "Freewire — Switching to a faster connection"
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
