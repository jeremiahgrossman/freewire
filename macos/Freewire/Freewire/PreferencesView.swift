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
    @State private var essentialsMode   = Preferences.shared.essentialsMode
    @State private var essentialsList   = Preferences.shared.essentialsAllowlist.joined(separator: ", ")
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

            Section("Restrictive networks") {
                VStack(alignment: .leading, spacing: 4) {
                    Toggle("Essentials Mode", isOn: $essentialsMode)
                        .onChange(of: essentialsMode) { _, v in Preferences.shared.essentialsMode = v }
                    Text("On networks too restrictive for a full VPN (some hotel and café wifi), carry only messaging, email, and push notifications, and block everything else. Most traffic will not go through Freewire. Off by default.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    if essentialsMode {
                        Text("Allowed destinations (comma-separated IPs, CIDRs, or domains):")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        TextField("17.0.0.0/8, signal.org", text: $essentialsList)
                            .textFieldStyle(.roundedBorder)
                            .font(.caption)
                            .onChange(of: essentialsList) { _, v in
                                let items = v.split(separator: ",")
                                    .map { $0.trimmingCharacters(in: .whitespaces) }
                                    .filter { !$0.isEmpty }
                                Preferences.shared.essentialsAllowlist = items
                            }
                        Text("Default: Apple 17.0.0.0/8 (iMessage + push, needs no DNS). Add a domain like signal.org or your mail server; domains resolve through the tunnel. Clearing this restores the default.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
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

    /// Copy is specified in `ux-workflows.md` and must match `privacy-policy.md`.
    ///
    /// "What you browse — We see only encrypted data" was here and was false. A
    /// VPN server forwards packets to their destination, so it necessarily knows
    /// the destination; and TLS still sends the hostname in the clear, so it
    /// currently sees that too. Packet capture on the server's own uplink showed
    /// wikipedia.org, github.com and duckduckgo.com in plain text while
    /// connected. Claiming otherwise in the one screen a user opens to check is
    /// worse than the exposure itself.
    ///
    /// The first flag marks what Freewire can see, not what it stores. Seeing a
    /// destination in order to forward to it and writing it down are different
    /// acts, and the second is the one that survives to be handed over.
    private let items: [(Bool, String, String)] = [
        (false, "Your IP address",    "Never logged."),
        (true,  "Which sites you connect to", "Visible while forwarding. Never recorded."),
        (false, "What you send and receive", "Encrypted end to end. We cannot read it."),
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
