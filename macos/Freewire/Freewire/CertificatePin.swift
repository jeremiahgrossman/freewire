import CryptoKit
import Foundation
import Security

/// Trust-on-first-use pinning for self-signed server certificates.
///
/// A server on a bare IP cannot hold a CA-signed certificate, so the client has
/// to accept one that chains to nothing. Accepting *any* certificate in that
/// case leaves the connection open to interception, and the control plane is not
/// empty: `POST /v1/peers` carries a Privacy Pass token, which an interceptor
/// can read and spend. The WireGuard key pin does not help there — it is checked
/// after the fact, and only against the config response.
///
/// So the certificate is pinned too. The first connection to a host records the
/// SHA-256 of its certificate's public key; every connection after that must
/// present the same one. This does not protect the very first connection, which
/// is the known limit of trust-on-first-use, and it closes every connection
/// after it.
///
/// The public key is pinned rather than the whole certificate so that renewing
/// a self-signed certificate with the same key does not lock the user out.
enum CertificatePin {

    /// Whether this trust chain is acceptable for `host`.
    static func accepts(_ trust: SecTrust, host: String) -> Bool {
        guard let fingerprint = leafKeyFingerprint(trust) else { return false }

        guard let recorded = pinned(for: host) else {
            record(fingerprint, for: host)
            return true
        }
        // Constant-time is not strictly required for public data, but
        // comparison routines get copied into places where it is.
        return constantTimeEquals(recorded, fingerprint)
    }

    /// Forgets the pin for a host, so the next connection re-establishes it.
    ///
    /// The user needs a way through when a server legitimately regenerates its
    /// certificate. Nothing calls this automatically: an automatic reset would
    /// turn the pin back into "accept anything", which is what it replaced.
    static func forget(host: String) {
        UserDefaults.standard.removeObject(forKey: key(for: host))
    }

    // MARK: - Storage

    private static func key(for host: String) -> String {
        "pinnedCertificate.\(host)"
    }

    private static func pinned(for host: String) -> String? {
        UserDefaults.standard.string(forKey: key(for: host))
    }

    private static func record(_ fingerprint: String, for host: String) {
        UserDefaults.standard.set(fingerprint, forKey: key(for: host))
    }

    // MARK: - Certificate

    /// SHA-256 over the leaf certificate's public key, base64-encoded.
    private static func leafKeyFingerprint(_ trust: SecTrust) -> String? {
        guard let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
              let leaf = chain.first,
              let key = SecCertificateCopyKey(leaf),
              let data = SecKeyCopyExternalRepresentation(key, nil) as Data? else {
            return nil
        }
        return Data(SHA256.hash(data: data)).base64EncodedString()
    }

    private static func constantTimeEquals(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        guard x.count == y.count else { return false }
        var diff: UInt8 = 0
        for i in x.indices { diff |= x[i] ^ y[i] }
        return diff == 0
    }
}
