import SwiftUI

// MARK: - Window controller

final class OnboardingWindowController: NSWindowController {

    static func show(tunnelManager: TunnelManager) {
        // Build the window first so the dismiss closure can reference it.
        let win = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 320),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        win.title = "Welcome to Freewire"
        win.isReleasedWhenClosed = false
        win.center()

        let wc = OnboardingWindowController(window: win)

        win.contentViewController = NSHostingController(
            rootView: OnboardingView(
                tunnelManager: tunnelManager,
                onDismiss: { [weak wc] in wc?.close() }
            )
        )

        wc.showWindow(nil)
        NSApp.activate(ignoringOtherApps: true)
        // Retain the controller for the lifetime of the window.
        objc_setAssociatedObject(win, &OnboardingWindowController.retainKey, wc, .OBJC_ASSOCIATION_RETAIN)
    }

    private static var retainKey = 0
}

// MARK: - Onboarding view (§3.3 Freewire Path, macOS)

struct OnboardingView: View {
    @ObservedObject var tunnelManager: TunnelManager
    let onDismiss: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            // Header
            VStack(spacing: 12) {
                Image(systemName: "shield.fill")
                    .font(.system(size: 48))
                    .foregroundStyle(.green)
                Text("Protect your connection\non any network.")
                    .font(.title2.weight(.semibold))
                    .multilineTextAlignment(.center)
                Text("Freewire works on hotel, airport, and café wifi\nthat blocks other VPNs.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding(.top, 40)
            .padding(.horizontal, 40)

            Spacer()

            // Action
            VStack(spacing: 10) {
                Button("Connect to Freewire") {
                    Preferences.shared.hasCompletedOnboarding = true
                    onDismiss()
                    Task { await tunnelManager.connect() }
                }
                .buttonStyle(OnboardingPrimaryButton())
                .frame(width: 240)

                // The AWS deploy flow lands in Phase 3. Until then the button
                // stays disabled: marking onboarding complete and dismissing
                // dropped the user on an unconfigured "Not protected" panel with
                // nothing to act on.
                Button("Set up self-hosting →") { }
                    .buttonStyle(.link)
                    .foregroundStyle(.tertiary)
                    .disabled(true)
                    .help("Self-hosted servers are coming in a later release.")
            }
            .padding(.bottom, 40)
        }
        .frame(width: 480, height: 320)
    }
}

private struct OnboardingPrimaryButton: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(.white)
            .padding(.vertical, 8)
            .frame(maxWidth: .infinity)
            .background(Color.accentColor.opacity(configuration.isPressed ? 0.8 : 1))
            .clipShape(RoundedRectangle(cornerRadius: 8))
    }
}
