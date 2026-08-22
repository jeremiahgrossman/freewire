import SwiftUI
import Combine

// MARK: - Root panel

struct PanelView: View {
    @ObservedObject var tunnelManager: TunnelManager
    let onPreferences: () -> Void
    let onQuit: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            PanelHeader(onPreferences: onPreferences)
            Divider()
            PanelBody(tunnelManager: tunnelManager)
            Divider()
            PanelFooter(onQuit: onQuit)
        }
        .frame(width: 240)
        .background(.background)
    }
}

// MARK: - Header

private struct PanelHeader: View {
    let onPreferences: () -> Void

    var body: some View {
        HStack {
            Text("Freewire")
                .font(.headline)
            Spacer()
            Button(action: onPreferences) {
                Image(systemName: "gearshape")
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
}

// MARK: - Body (state-driven)

private struct PanelBody: View {
    @ObservedObject var tunnelManager: TunnelManager

    var body: some View {
        Group {
            switch tunnelManager.state {
            case .disconnected:
                DisconnectedBody(tunnelManager: tunnelManager)
            case .connecting(let status):
                ConnectingBody(status: status, tunnelManager: tunnelManager)
            case .connected(_, _, let connectedAt, let transport):
                ConnectedBody(connectedAt: connectedAt, transport: transport, tunnelManager: tunnelManager)
            case .reconnecting(let attempt):
                ReconnectingBody(attempt: attempt, tunnelManager: tunnelManager)
            case .blocked:
                BlockedBody(tunnelManager: tunnelManager)
            case .captivePortal(let url):
                CaptivePortalBody(redirectURL: url, tunnelManager: tunnelManager)
            case .networkBlock:
                NetworkBlockBody(tunnelManager: tunnelManager)
            case .awaitingPortalAuth(let timedOut):
                AwaitingPortalBody(timedOut: timedOut, tunnelManager: tunnelManager)
            case .upgrading:
                UpgradingBody()
            case .noNetwork:
                NoNetworkBody(tunnelManager: tunnelManager)
            case .failed(let error):
                FailedBody(error: error, tunnelManager: tunnelManager)
            }
        }
        .padding(12)
    }
}

// MARK: - Disconnected

private struct DisconnectedBody: View {
    @ObservedObject var tunnelManager: TunnelManager

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            StatusRow(symbol: "circle", label: "Not protected", color: .secondary)
            Text("Traffic is not encrypted on this network.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer().frame(height: 4)
            ConnectButton(tunnelManager: tunnelManager)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Connecting

private struct ConnectingBody: View {
    let status: String
    @ObservedObject var tunnelManager: TunnelManager

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                ProgressView().scaleEffect(0.6)
                Text("Connecting...")
                    .font(.subheadline.weight(.medium))
            }
            Text(status)
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer().frame(height: 4)
            Button("Cancel") {
                tunnelManager.cancelConnect()
            }
            .buttonStyle(SecondaryButtonStyle())
            .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Connected

private struct ConnectedBody: View {
    let connectedAt: Date
    let transport: TunnelTransport
    @ObservedObject var tunnelManager: TunnelManager
    @State private var now = Date()
    // Connected on appear and cancelled on disappear rather than autoconnected:
    // the popover is closed almost all of the time, and a timer firing every
    // second behind it is pure wakeups for a view nobody is looking at.
    private let ticker = Timer.publish(every: 1, on: .main, in: .common)
    @State private var tickerConnection: Cancellable?

    var duration: String {
        let secs = max(0, Int(now.timeIntervalSince(connectedAt)))
        // Below a minute, show seconds. "0 min" for the first full minute read
        // as a broken timer at exactly the moment the user is checking it.
        if secs < 60 { return "\(secs) sec" }
        let mins = secs / 60
        if mins < 60 { return "\(mins) min" }
        return "\(mins / 60) hr \(mins % 60) min"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // DEBUG-1, per error-states-spec.md. With routing skipped the
            // tunnel is genuinely up and genuinely carrying nothing, so the
            // headline is replaced rather than annotated: a caution underneath
            // a green "Protected" reads as a footnote to protection, and there
            // is no protection.
            if Preferences.shared.skipRouting {
                StatusRow(symbol: "exclamationmark.triangle.fill",
                          label: "Debug mode: routing off", color: .orange)
                Text("Your traffic is NOT going through the VPN.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            } else {
                StatusRow(symbol: "checkmark.shield.fill", label: "Protected", color: .green)
            }
            Text("Connected · \(duration)")
                .font(.caption)
                .foregroundStyle(.secondary)
            if transport != .wireguard {
                TransportIndicator(transport: transport)
            }
            // DNS-1, per error-states-spec.md. Shown below the status rather
            // than replacing it, because the status is true: the tunnel is
            // carrying traffic and encrypting it. Only the lookups are exposed.
            if transport.leaksDNSToNetwork {
                Text("Your traffic is protected, but this network can see which sites you visit.")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer().frame(height: 4)
            Button("Disconnect") {
                Task { await tunnelManager.disconnect() }
            }
            .buttonStyle(PrimaryButtonStyle())
            .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .onReceive(ticker) { t in now = t }
        .onAppear {
            now = Date()
            tickerConnection = ticker.connect()
        }
        .onDisappear {
            tickerConnection?.cancel()
            tickerConnection = nil
        }
    }
}

// Transport badge shown when connected on a non-WireGuard path.
private struct TransportIndicator: View {
    let transport: TunnelTransport

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: transport.isReducedSpeed ? "tortoise.fill" : "arrow.triangle.2.circlepath")
                .font(.caption2)
            Text(transport.isReducedSpeed ? "Reduced speed · \(transport.displayName)" : transport.displayName)
                .font(.caption2)
        }
        .foregroundStyle(transport.isReducedSpeed ? Color.orange : Color.secondary)
    }
}

// MARK: - Awaiting portal sign-in

/// Shown while Freewire waits out a captive portal login.
///
/// CONN-2a promises "Freewire will reconnect automatically"; previously the
/// panel dropped straight to "Not protected", contradicting the sentence the
/// user had just read and hiding the fact that anything was still happening.
private struct AwaitingPortalBody: View {
    let timedOut: Bool
    @ObservedObject var tunnelManager: TunnelManager

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                if !timedOut { ProgressView().scaleEffect(0.6) }
                Text(timedOut ? "Still not connected" : "Waiting for you to finish signing in…")
                    .font(.subheadline.weight(.medium))
                    .fixedSize(horizontal: false, vertical: true)
            }
            Text(timedOut
                 ? "Finish signing in to this network, then try again."
                 : "Freewire will connect as soon as this network lets it through.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer().frame(height: 4)
            if timedOut {
                Button("Try again") { tunnelManager.retryPortalWait() }
                    .buttonStyle(PrimaryButtonStyle())
                    .frame(maxWidth: .infinity)
            }
            Button("Cancel") {
                Task { await tunnelManager.disconnect() }
            }
            .buttonStyle(SecondaryButtonStyle())
            .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - No network (CONN-1)

private struct NoNetworkBody: View {
    @ObservedObject var tunnelManager: TunnelManager

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("No internet connection")
                .font(.subheadline.weight(.medium))
            // Copy per error-states-spec.md CONN-1.
            Text("Connect to a network and try again.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer().frame(height: 4)
            Button("Try again") {
                Task { await tunnelManager.connect() }
            }
            .buttonStyle(PrimaryButtonStyle())
            .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Reconnecting

private struct ReconnectingBody: View {
    let attempt: Int
    @ObservedObject var tunnelManager: TunnelManager

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 6) {
                ProgressView().scaleEffect(0.6)
                Text("Reconnecting...")
                    .font(.subheadline.weight(.medium))
            }
            Text("Attempt \(attempt + 1) of 3. Your traffic is not protected while reconnecting.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer().frame(height: 4)
            // F13: the full sentence overflowed the 240pt panel. The explanation
            // lives in the caption above.
            Button("Disconnect") {
                Task { await tunnelManager.disconnect() }
            }
            .buttonStyle(SecondaryButtonStyle())
            .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Blocked

private struct BlockedBody: View {
    @ObservedObject var tunnelManager: TunnelManager

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            StatusRow(symbol: "exclamationmark.circle.fill", label: "Connection lost", color: .red)
            Text("Reconnection failed. Your traffic is not protected. Reconnect or disconnect.")
                .font(.caption)
                .foregroundStyle(.secondary)
            Spacer().frame(height: 4)
            Button("Try Again") {
                Task { await tunnelManager.retryFromBlocked() }
            }
            .buttonStyle(PrimaryButtonStyle())
            .frame(maxWidth: .infinity)
            Button("Disconnect") {
                Task { await tunnelManager.disconnect() }
            }
            .buttonStyle(SecondaryButtonStyle())
            .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Captive portal (CONN-2a)

private struct CaptivePortalBody: View {
    let redirectURL: URL?
    @ObservedObject var tunnelManager: TunnelManager

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            StatusRow(symbol: "wifi.exclamationmark", label: "Network login required", color: .orange)
            // Exact copy from error-states-spec.md CONN-2a
            Text("Authenticate with this network, then Freewire will reconnect automatically.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer().frame(height: 4)
            Button("Open Network Login") {
                tunnelManager.openCaptivePortal(url: redirectURL)
            }
            .buttonStyle(PrimaryButtonStyle())
            .frame(maxWidth: .infinity)
            Button("Cancel") {
                Task { await tunnelManager.disconnect() }
            }
            .buttonStyle(SecondaryButtonStyle())
            .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Network block (CONN-2b)

private struct NetworkBlockBody: View {
    @ObservedObject var tunnelManager: TunnelManager

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            StatusRow(symbol: "xmark.shield.fill", label: "This network is blocking secure connections.", color: .red)
            // Exact copy from error-states-spec.md CONN-2b
            Text("Freewire tried every available method. This network may restrict all VPN traffic.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            Spacer().frame(height: 4)
            Button("Try Again") {
                Task { await tunnelManager.retryFromNetworkBlock() }
            }
            .buttonStyle(PrimaryButtonStyle())
            .frame(maxWidth: .infinity)
            Button("Disconnect") {
                Task { await tunnelManager.disconnect() }
            }
            .buttonStyle(SecondaryButtonStyle())
            .frame(maxWidth: .infinity)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Failed

private struct FailedBody: View {
    let error: Error
    @ObservedObject var tunnelManager: TunnelManager

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            StatusRow(symbol: "xmark.circle.fill", label: "Failed to connect", color: .red)
            Text(error.localizedDescription)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(4)
            Spacer().frame(height: 4)
            ConnectButton(tunnelManager: tunnelManager)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

// MARK: - Footer

private struct PanelFooter: View {
    let onQuit: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            FooterButton(label: "What is a VPN?") {
                if let url = URL(string: "https://freewire.com/what-is-a-vpn") {
                    NSWorkspace.shared.open(url)
                }
            }
            FooterButton(label: "Quit Freewire", action: onQuit)
        }
    }
}

private struct FooterButton: View {
    let label: String
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 12)
                .padding(.vertical, 6)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(.secondary)
        .font(.subheadline)
    }
}

// MARK: - Shared components

private struct StatusRow: View {
    let symbol: String
    let label: String
    let color: Color

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: symbol)
                .foregroundStyle(color)
            Text(label)
                .font(.subheadline.weight(.semibold))
        }
    }
}

private struct ConnectButton: View {
    @ObservedObject var tunnelManager: TunnelManager

    var body: some View {
        Button("Connect") {
            Task { await tunnelManager.connect() }
        }
        .buttonStyle(PrimaryButtonStyle())
        .frame(maxWidth: .infinity)
    }
}

// MARK: - Button styles

struct PrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.subheadline.weight(.medium))
            .foregroundStyle(.white)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity)
            .background(Color.accentColor.opacity(configuration.isPressed ? 0.75 : 1))
            .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

struct SecondaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.subheadline)
            .foregroundStyle(.primary)
            .padding(.vertical, 6)
            .frame(maxWidth: .infinity)
            .background(Color.secondary.opacity(configuration.isPressed ? 0.2 : 0.1))
            .clipShape(RoundedRectangle(cornerRadius: 6))
    }
}

/// UPGRADE-1, per error-states-spec.md.
///
/// The tunnel is being rebuilt on a faster path. For that window there is no
/// tunnel: the helper has exited, the routes are gone, and traffic is on the
/// normal path. The panel used to keep showing "Protected" throughout, which is
/// the same defect as DEBUG-1 and worse for happening during ordinary
/// successful operation rather than only under a debug preference.
///
/// No Cancel button: the window is a handshake and a route install, and a
/// control that outlives what it acts on is its own bug. Disconnect remains
/// available from the menu and does cancel the upgrade.
struct UpgradingBody: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            StatusRow(symbol: "arrow.triangle.2.circlepath",
                      label: "Switching to a faster connection", color: .orange)
            Text("Your traffic is not protected for a moment.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
