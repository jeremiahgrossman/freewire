import CryptoKit
import Foundation
import Security

enum TokenError: Error, LocalizedError {
    /// The Privacy Pass issuer key changed since first use. A hard block.
    case issuerKeyChanged   // TRUST-4

    var errorDescription: String? {
        switch self {
        // Exact copy from error-states-spec.md TRUST-4. It shares TRUST-2's
        // string deliberately: to the user both are the same event -- the server
        // is not the one this client trusts -- and the distinction between a
        // WireGuard key and a token-issuer key is not one the message should ask
        // them to hold. Do not paraphrase.
        case .issuerKeyChanged:
            return "This server's identity does not match the one Freewire trusts. Connection refused."
        }
    }
}

/// Holds unspent Privacy Pass tokens and requests more when they run low.
///
/// Tokens are anonymous credentials, not secrets tied to this device, so they
/// live in their own file rather than beside the device key in the Keychain —
/// per the spec, and because that pairing would associate an anonymous
/// credential with the identity it exists to be independent of. The file is
/// encrypted under a random key that the Keychain does hold, since a token is
/// still a bearer credential and the file is otherwise readable by anything
/// running as this user.
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
    /// Set once a refresh sees the issuer key change since first use (the
    /// `freewire-tokens` helper exits with `issuerKeyChangedExitCode`). Once
    /// true, `take()` hard-blocks instead of vending, per error-states-spec.md
    /// TRUST-4: a changed issuer key is a trust failure, not a transient
    /// issuance failure, and following it is exactly the tagging attack blind
    /// signing exists to prevent. It stays set for the process lifetime; a
    /// legitimate rotation requires deleting the pin file (see checkPin in the
    /// helper), which is the intended cost.
    private var issuerKeyChanged = false
    /// The in-flight refresh, so concurrent callers wait for the batch rather
    /// than returning empty-handed. A plain bool made the second caller give up
    /// and register without a token, which a token-issuing server refuses.
    private var refreshTask: Task<Void, Never>?
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
    ///
    /// Throws `TokenError.issuerKeyChanged` (TRUST-4) when a refresh found the
    /// issuer key changed since first use. That is a hard block, not a
    /// fall-through to token-less registration: the caller surfaces it verbatim
    /// and refuses to connect.
    func take() async throws -> String? {
        if tokens.isEmpty {
            await refresh()
        }
        // TRUST-4: refuse before vending anything, even if a stockpile remains.
        // Once we have seen the issuer key change, no token from this issuer is
        // trustworthy to present.
        if issuerKeyChanged {
            throw TokenError.issuerKeyChanged
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
        if let inFlight = refreshTask {
            await inFlight.value
            return
        }
        let task = Task { await self.doRefresh() }
        refreshTask = task
        await task.value
        refreshTask = nil
    }

    private func doRefresh() async {
        guard let helper = Self.helperURL else { return }

        var args = ["issue", "--server", serverBase, "--count", String(Self.batchSize)]
        if allowSelfSigned {
            args.append("--insecure")
        }
        // Pin the issuer key on first use. Blind signing hides the token from
        // the issuer but not which key signed it, so an issuer that hands every
        // client a distinct keypair learns at redemption exactly which client a
        // token came from — with every signature still verifying and no error
        // raised anywhere. A key-consistency check is the only thing that
        // catches it, and this file is where the first-seen key is recorded.
        if let pin = Self.issuerPinURL {
            args.append(contentsOf: ["--issuer-pin", pin.path])
        }

        let result = await Task.detached { () -> (out: String?, status: Int32) in
            let p = Process()
            p.executableURL = helper
            p.arguments = args
            let pipe = Pipe()
            p.standardOutput = pipe
            p.standardError = FileHandle.nullDevice
            guard (try? p.run()) != nil else { return (nil, -1) }

            // Bound the wait. Issuance sits directly in front of a connect
            // attempt, so a helper that hangs — a server that accepts and never
            // answers, a stalled DNS lookup — held connect() open forever with
            // no timeout anywhere in the chain to break it.
            let deadline = DispatchTime.now() + Self.issueTimeout
            let killer = DispatchWorkItem { if p.isRunning { p.terminate() } }
            DispatchQueue.global().asyncAfter(deadline: deadline, execute: killer)

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            killer.cancel()

            let status = p.terminationStatus
            guard status == 0 else { return (nil, status) }
            return (String(data: data, encoding: .utf8), status)
        }.value

        // TRUST-4: the helper's dedicated exit code says the pinned issuer key
        // changed since first use. Record it so take() hard-blocks; do not treat
        // it as an ordinary issuance failure. Kept in sync with the helper's
        // exitIssuerKeyChanged.
        if result.status == Self.issuerKeyChangedExitCode {
            issuerKeyChanged = true
        }

        guard let out = result.out else { return }
        // Trimmed of newlines as well as spaces. A token is placed verbatim in
        // an Authorization header, and a stray carriage return there ends the
        // header and begins whatever follows it.
        let fresh = out.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty && $0.allSatisfy(Self.isTokenCharacter) }
        guard !fresh.isEmpty else { return }

        // Shuffled before storing. Tokens are handed out in the order they are
        // held, so a batch spent in issuance order tells the server which
        // redemptions came from one batch and in what sequence they were
        // signed — a correlation the blind signature otherwise denies it.
        tokens.append(contentsOf: fresh.shuffled())
        Self.save(tokens)
    }

    /// Base64url alphabet. Anything else did not come from the issuer.
    private static func isTokenCharacter(_ c: Character) -> Bool {
        c.isLetter && c.isASCII || c.isNumber && c.isASCII || c == "-" || c == "_"
    }

    /// Ceiling on one issuance run, inside the 10-second connect budget.
    private static let issueTimeout: DispatchTimeInterval = .seconds(8)

    /// Exit code the `freewire-tokens` helper uses for a changed issuer key.
    /// Kept in sync with the helper's `exitIssuerKeyChanged`. TRUST-4.
    private static let issuerKeyChangedExitCode: Int32 = 3

    // MARK: - Storage

    private static var appDirectory: URL? {
        guard let dir = FileManager.default.urls(
            for: .applicationSupportDirectory, in: .userDomainMask
        ).first else { return nil }
        let appDir = dir.appendingPathComponent("Freewire", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: appDir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        return appDir
    }

    private static var storeURL: URL? {
        appDirectory?.appendingPathComponent("tokens.bin")
    }

    /// Records the fingerprint of the issuer key seen on first issuance.
    private static var issuerPinURL: URL? {
        appDirectory?.appendingPathComponent("issuer-key.pin")
    }

    /// Account holding the key that encrypts the token file at rest.
    ///
    /// The tokens are encrypted rather than stored in the Keychain directly,
    /// which keeps the property the store was built for: a token must not sit
    /// beside the device key, because the pairing would associate an anonymous
    /// credential with the identity it exists to be independent of. What lives
    /// in the Keychain is a random file key that says nothing about either.
    private static let fileKeyAccount = "token_store_key"

    private static func fileKey() -> SymmetricKey? {
        if let existing = try? KeychainHelper.load(account: fileKeyAccount),
           existing.count == 32 {
            return SymmetricKey(data: existing)
        }
        var raw = Data(count: 32)
        let ok = raw.withUnsafeMutableBytes { buf in
            SecRandomCopyBytes(kSecRandomDefault, 32, buf.baseAddress!) == errSecSuccess
        }
        guard ok, (try? KeychainHelper.store(raw, account: fileKeyAccount)) != nil else {
            return nil
        }
        return SymmetricKey(data: raw)
    }

    private static func load() -> [String] {
        guard let url = storeURL,
              let box = try? Data(contentsOf: url),
              let key = fileKey(),
              let sealed = try? AES.GCM.SealedBox(combined: box),
              let plain = try? AES.GCM.open(sealed, using: key),
              let text = String(data: plain, encoding: .utf8) else { return [] }
        return text.split(separator: "\n").map(String.init).filter { !$0.isEmpty }
    }

    private static func save(_ tokens: [String]) {
        guard let url = storeURL else { return }
        // Tokens are anonymous credentials, so leaking one costs bandwidth
        // rather than privacy — but a plaintext file is still a bearer
        // credential readable by anything running as this user, and the file
        // protection option that used to stand in for encryption here is an iOS
        // API that does nothing at all on macOS.
        guard let key = fileKey(),
              let sealed = try? AES.GCM.seal(Data(tokens.joined(separator: "\n").utf8), using: key),
              let box = sealed.combined else { return }
        try? box.write(to: url, options: [.atomic])
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
