import Foundation
import CryptoKit

private let kPrivateKeyAccount = "wg-private-key"

final class DeviceIdentity {

    private(set) var privateKey: Curve25519.KeyAgreement.PrivateKey
    var publicKey: Curve25519.KeyAgreement.PublicKey { privateKey.publicKey }

    var publicKeyBase64: String {
        publicKey.rawRepresentation.base64EncodedString()
    }

    var privateKeyBase64: String {
        privateKey.rawRepresentation.base64EncodedString()
    }

    /// Colon-separated hex of the first 8 bytes. Example: "AB:CD:EF:12:34:56:78:9A"
    var fingerprint: String {
        publicKey.rawRepresentation
            .prefix(8)
            .map { String(format: "%02X", $0) }
            .joined(separator: ":")
    }

    init() throws {
        do {
            let keyData = try KeychainHelper.load(account: kPrivateKeyAccount)
            privateKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: keyData)
        } catch KeychainError.itemNotFound {
            privateKey = try DeviceIdentity.generateAndStore()
        }
    }

    func reset() throws {
        privateKey = try DeviceIdentity.generateAndStore()
    }

    func removeFromKeychain() throws {
        try KeychainHelper.delete(account: kPrivateKeyAccount)
    }

    private static func generateAndStore() throws -> Curve25519.KeyAgreement.PrivateKey {
        let key = Curve25519.KeyAgreement.PrivateKey()
        try KeychainHelper.store(key.rawRepresentation, account: kPrivateKeyAccount)
        return key
    }
}
