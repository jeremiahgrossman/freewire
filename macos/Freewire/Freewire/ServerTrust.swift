import Foundation

/// Decides whether a server's identity can be trusted.
///
/// The API is where the client learns the server's WireGuard public key, and
/// that key is the trust anchor for the whole tunnel: whoever supplies it can
/// terminate the tunnel and read everything inside it. Transport security alone
/// is not enough, because a single mis-issued certificate for the API host
/// would be enough to swap the key — so the key is pinned independently of the
/// certificate that delivered it.
enum ServerTrust {

    /// WireGuard public keys accepted for the managed server.
    ///
    /// More than one so a key can be rotated without stranding clients: publish
    /// the successor here, ship it, and only then switch the server over. A
    /// single-valued pin would make every rotation a forced-update event.
    static let managedServerKeys: Set<String> = [
        // Populated at release time with the managed server's public key(s).
        // Empty during development, which `isPinned` treats as "no managed
        // server configured" rather than "trust anything".
    ]

    /// A key the user supplied out of band for a self-hosted server.
    ///
    /// Servers on a bare IP cannot hold a CA-signed certificate, so there is no
    /// authenticated channel to learn their key over. The user carries it
    /// across themselves — pasted or scanned from the server dashboard — and
    /// that value, not the certificate, is what makes the server trustworthy.
    /// Read straight from UserDefaults rather than through Preferences.
    ///
    /// Preferences is main-actor isolated, and this is consulted from the
    /// URLSession trust callback, which runs on a background queue. Going
    /// through the singleton there silently yielded no pin, so the delegate
    /// fell through to default validation and rejected the very certificate the
    /// pin exists to accept. UserDefaults is thread-safe, so the hop bought
    /// nothing.
    static var userPinnedKey: String? {
        get {
            let v = UserDefaults.standard.string(forKey: "pinnedServerKey")
            return (v?.isEmpty ?? true) ? nil : v
        }
        set { UserDefaults.standard.set(newValue, forKey: "pinnedServerKey") }
    }

    /// The host the user's pin belongs to.
    ///
    /// A pin with no host was honoured for every server, which had two
    /// consequences worth separating. It meant a key pinned for one server was
    /// accepted as proof of identity for a different one. And because
    /// `trustsSelfSignedCertificate` was derived from the pin's mere existence,
    /// pinning a self-hosted server also switched off certificate validation
    /// for the managed server — a self-hosted user silently lost CA validation
    /// everywhere. Empty means "applies to whichever server is configured",
    /// which preserves the behaviour for anyone who set a pin before this
    /// existed.
    static var userPinnedHost: String? {
        get {
            let v = UserDefaults.standard.string(forKey: "pinnedServerHost")
            return (v?.isEmpty ?? true) ? nil : v
        }
        set { UserDefaults.standard.set(newValue, forKey: "pinnedServerHost") }
    }

    /// Whether the user's pin applies to `host`.
    private static func userPinApplies(to host: String) -> Bool {
        guard let pinned = userPinnedKey, !pinned.isEmpty else { return false }
        guard let pinnedHost = userPinnedHost else { return true }
        return pinnedHost.caseInsensitiveCompare(host) == .orderedSame
    }

    /// Whether `key` is an acceptable identity for `host`.
    static func accepts(key: String, host: String) -> Bool {
        if userPinApplies(to: host), let pinned = userPinnedKey {
            return constantTimeEquals(key, pinned)
        }
        guard !managedServerKeys.isEmpty else { return false }
        for candidate in managedServerKeys where constantTimeEquals(key, candidate) {
            return true
        }
        return false
    }

    /// Whether a self-signed certificate should be accepted for `host`.
    ///
    /// One predicate for the whole client. The TLS transports used an RFC 1918
    /// address test while the control plane used the pin, so against a pinned
    /// server on a routable address the API connected and every TLS transport
    /// then failed certificate validation.
    ///
    /// Scoped to the host, because "the user pinned something, somewhere" is not
    /// a reason to stop validating certificates for a server they did not pin.
    static func trustsSelfSignedCertificate(host: String) -> Bool {
        userPinApplies(to: host)
    }

    /// Whether any pin is configured at all for `host`.
    ///
    /// Distinguishes "this build has no managed server and the user has not
    /// supplied a key" from "the key presented does not match", so the client
    /// can explain which of the two happened.
    static func isPinned(host: String) -> Bool {
        userPinApplies(to: host) || !managedServerKeys.isEmpty
    }

    /// Compares without leaking where two keys diverge.
    ///
    /// A public key is not secret, so this is belt and braces rather than
    /// strictly required — but comparison routines get copied, and the copy is
    /// not always about public data.
    private static func constantTimeEquals(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        guard x.count == y.count else { return false }
        var diff: UInt8 = 0
        for i in x.indices { diff |= x[i] ^ y[i] }
        return diff == 0
    }
}
