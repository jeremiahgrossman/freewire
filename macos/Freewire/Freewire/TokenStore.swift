import Foundation

/// Holds unspent Privacy Pass tokens and requests more when they run low.
///
/// Tokens are anonymous credentials, not secrets tied to this device, so they
/// live in a protected file rather than the Keychain — per the spec, and
/// because putting them beside the device key would associate the two.
///
/// The blinding itself happens in the `freewire-tokens` helper. RFC 9474 needs
/// EMSA-PSS encoding, modular multiplication and modular inversion over
/// 2048-bit integers, none of which Security.framework exposes; a Swift
/// implementation would mean hand-rolling all three. A subtly wrong blinding
/// factor still yields tokens the server accepts while leaking the linkage the
/// scheme exists to prevent, so the failure would be silent and the guarantee
/// gone. Sharing the implementation the server verifies against removes the
/// possibility of the two drifting apart.
@MainActor
final class TokenStore {

    /// Below this, a refresh is started in the background.
    private static let lowWaterMark = 3
    /// Requested per batch. The server caps a batch at 20.
    private static let batchSize = 10

    private var tokens: [String] = []
    private var refreshing = false
    private let serverBase: String
    private let allowSelfSigned: Bool

    init(serverBase: String, allowSelfSigned: Bool) {
        self.serverBase = serverBase
        self.allowSelfSigned = allowSelfSigned
        tokens = Self.load()
    }

    var count: Int { tokens.count }

    /// Takes a token, fetching a batch first if none are held.
    ///
    /// Returns nil when the server does not issue tokens (self-hosted) or
    /// issuance failed. The caller registers without one and lets the server
    /// decide, rather than refusing to connect over a rate-limiting mechanism.
    func take() async -> String? {
        if tokens.isEmpty {
            await refresh()
        }
        guard !tokens.isEmpty else { return nil }

        let token = tokens.removeFirst()
        Self.save(tokens)

        if tokens.count < Self.lowWaterMark {
            // Refill in the background: the point of a batch is that the next
            // connection does not pay for issuance.
            Task { await refresh() }
        }
        return token
    }

    /// Fetches a batch. Concurrent calls collapse into one.
    func refresh() async {
        guard !refreshing else { return }
        refreshing = true
        defer { refreshing = false }

        guard let helper = Self.helperURL else { return }

        var args = ["issue", "--server", serverBase, "--count", String(Self.batchSize)]
        if allowSelfSigned {
            args.append("--insecure")
        }

        let out = await Task.detached { () -> String? in
            let p = Process()
            p.executableURL = helper
            p.arguments = args
            let pipe = Pipe()
            p.standardOutput = pipe
            p.standardError = FileHandle.nullDevice
            guard (try? p.run()) != nil else { return nil }
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            guard p.terminationStatus == 0 else { return nil }
            return String(data: data, encoding: .utf8)
        }.value

        guard let out else { return }
        let fresh = out.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard !fresh.isEmpty else { return }

        tokens.append(contentsOf: fresh)
        Self.save(tokens)
    }

    // MARK: - Storage

    private static var storeURL: URL? {
        guard let dir = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first else { return nil }
        let appDir = dir.appendingPathComponent("Freewire", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: appDir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return appDir.appendingPathComponent("tokens.bin")
    }

    private static func load() -> [String] {
        guard let url = storeURL,
              let data = try? Data(contentsOf: url),
              let text = String(data: data, encoding: .utf8) else { return [] }
        return text.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
    }

    private static func save(_ tokens: [String]) {
        guard let url = storeURL else { return }
        let data = Data(tokens.joined(separator: "\n").utf8)
        try? data.write(to: url, options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication])
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600], ofItemAtPath: url.path
        )
    }

    private static var helperURL: URL? {
        if let bundled = Bundle.main.executableURL?
            .deletingLastPathComponent()
            .appendingPathComponent("freewire-tokens"),
           FileManager.default.isExecutableFile(atPath: bundled.path) {
            return bundled
        }
        #if DEBUG
        let dev = URL(fileURLWithPath: NSHomeDirectory())
            .appendingPathComponent("Claude/Projects/FreewireVPN/tunnel/freewire-tokens")
        return FileManager.default.isExecutableFile(atPath: dev.path) ? dev : nil
        #else
        return nil
        #endif
    }
}
