import SwiftUI

// MARK: - Window controller

final class PreferencesWindowController: NSWindowController {
    static let shared = PreferencesWindowController()

    private init() {
        let vc = NSHostingController(rootView: PreferencesView())
        let win = NSWindow(contentViewController: vc)
        win.title = "Freewire Preferences"
        win.styleMask = [.titled, .closable]
        win.setContentSize(NSSize(width: 400, height: 440))
        win.center()
        win.isReleasedWhenClosed = false
        super.init(window: win)
    }

    required init?(coder: NSCoder) { fatalError() }
}

// MARK: - Preferences view

struct PreferencesView: View {
    @State private var killSwitch       = Preferences.shared.killSwitchEnabled
    @State private var autoConnect      = Preferences.shared.autoConnect
    @State private var launchAtLogin    = Preferences.shared.launchAtLogin
    @State private var netIntelligence  = Preferences.shared.networkIntelligenceEnabled
    @State private var fingerprint      = (try? DeviceIdentity())?.fingerprint ?? "—"
    @State private var showPrivacyDetail = false

    var body: some View {
        Form {
            Section("General") {
                Toggle("Launch at login", isOn: $launchAtLogin)
                    .onChange(of: launchAtLogin) { _, v in Preferences.shared.launchAtLogin = v }
                Toggle("Connect automatically on launch", isOn: $autoConnect)
                    .onChange(of: autoConnect) { _, v in Preferences.shared.autoConnect = v }
            }

            Section("Protection") {
                VStack(alignment: .leading, spacing: 4) {
                    // Disabled until FreewireHelper installs the pf rules. The
                    // control previously defaulted to on and promised protection
                    // on public networks that nothing enforced. Copy per
                    // error-states-spec.md "Interim: kill switch not yet enforced".
                    Toggle("Kill switch", isOn: $killSwitch)
                        .onChange(of: killSwitch) { _, v in Preferences.shared.killSwitchEnabled = v }
                        .disabled(true)
                    Text("Not available yet. When the VPN drops, traffic is not blocked. Coming in a future release.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section("Privacy") {
                Button("What Freewire sees \u{203A}") {
                    showPrivacyDetail = true
                }
                .buttonStyle(.link)
                VStack(alignment: .leading, spacing: 4) {
                    Toggle("Help improve captive portal detection", isOn: $netIntelligence)
                        .onChange(of: netIntelligence) { _, v in Preferences.shared.networkIntelligenceEnabled = v }
                    Text("Shares which connection method worked on this network. No personal data collected.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Section("Device") {
                LabeledContent("Key fingerprint", value: fingerprint)
                    .font(.system(.body, design: .monospaced))
            }

            Section("About") {
                LabeledContent("Version", value: Bundle.main.shortVersion)
                Button("Check for Updates") { /* Sparkle integration — Phase 3 */ }
                    .buttonStyle(.link)
                Button("Privacy Policy") {
                    if let url = URL(string: "https://freewire.com/privacy") { NSWorkspace.shared.open(url) }
                }
                .buttonStyle(.link)
            }
        }
        .formStyle(.grouped)
        .frame(width: 400, height: 440)
        .sheet(isPresented: $showPrivacyDetail) {
            PrivacyDetailView()
        }
    }
}

// MARK: - "What Freewire sees" sheet

private struct PrivacyDetailView: View {
    @Environment(\.dismiss) var dismiss

    private let items: [(Bool, String, String)] = [
        (false, "Your IP address",    "Never logged."),
        (false, "What you browse",    "We see only encrypted data."),
        (false, "When you connected", "No connection logs."),
        (false, "Your identity",      "No account. No email."),
        (true,  "Anonymous rate-limit tokens", "Cryptographically unlinked to your device. Deleted after 30 days."),
    ]

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text("What Freewire sees")
                    .font(.headline)
                Spacer()
                Button("Done") { dismiss() }
            }
            .padding()

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    ForEach(items, id: \.1) { item in
                        HStack(alignment: .top, spacing: 10) {
                            Image(systemName: item.0 ? "checkmark.circle.fill" : "xmark.circle.fill")
                                .foregroundStyle(item.0 ? .green : .red)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(item.1).font(.subheadline.weight(.medium))
                                Text(item.2).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
                .padding()
            }

            Divider()

            Button("Read our privacy policy") {
                if let url = URL(string: "https://freewire.com/privacy") { NSWorkspace.shared.open(url) }
            }
            .buttonStyle(.link)
            .padding()
        }
        .frame(width: 360, height: 340)
    }
}

// MARK: - Helpers

private extension Bundle {
    var shortVersion: String {
        infoDictionary?["CFBundleShortVersionString"] as? String ?? "—"
    }
}
