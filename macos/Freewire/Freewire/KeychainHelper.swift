import Foundation
import Security

private let kService = "com.freewire.vpn"

enum KeychainError: Error, LocalizedError {
    case unexpectedStatus(OSStatus)
    case unexpectedData
    case itemNotFound

    var errorDescription: String? {
        switch self {
        case .unexpectedStatus(let s): return "Keychain OSStatus \(s)."
        case .unexpectedData:          return "Keychain returned unexpected data."
        case .itemNotFound:            return "Keychain item not found."
        }
    }
}

enum KeychainHelper {

    static func store(_ data: Data, account: String) throws {
        // Try updating an existing item first.
        let updateQuery: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: kService,
            kSecAttrAccount as String: account,
        ]
        let attrs: [String: Any] = [kSecValueData as String: data]
        let updateStatus = SecItemUpdate(updateQuery as CFDictionary, attrs as CFDictionary)

        if updateStatus == errSecItemNotFound {
            // Item doesn't exist yet — add it.
            // No kSecAttrAccess / kSecUseDataProtectionKeychain: both require entitlements
            // (keychain-access-groups) or trigger legacy SecAccessCreate which fails on
            // modern macOS (missing /private/var/db/DetachedSignatures). The first access
            // from a new code signature shows a one-time "Always Allow" dialog — click it
            // once and the ACL is updated for all future builds of this app.
            let addQuery: [String: Any] = [
                kSecClass as String:           kSecClassGenericPassword,
                kSecAttrService as String:     kService,
                kSecAttrAccount as String:     account,
                kSecAttrAccessible as String:  kSecAttrAccessibleAfterFirstUnlock,
                kSecValueData as String:       data,
            ]
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw KeychainError.unexpectedStatus(addStatus)
            }
        } else if updateStatus != errSecSuccess {
            throw KeychainError.unexpectedStatus(updateStatus)
        }
    }

    static func load(account: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: kService,
            kSecAttrAccount as String: account,
            kSecReturnData as String:  true,
            kSecMatchLimit as String:  kSecMatchLimitOne,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound { throw KeychainError.itemNotFound }
        guard status == errSecSuccess   else { throw KeychainError.unexpectedStatus(status) }
        guard let data = result as? Data else { throw KeychainError.unexpectedData }
        return data
    }

    static func delete(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String:       kSecClassGenericPassword,
            kSecAttrService as String: kService,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unexpectedStatus(status)
        }
    }
}
