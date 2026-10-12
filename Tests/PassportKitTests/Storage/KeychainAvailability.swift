import Foundation
import Security

/// Whether this test process can write to the Keychain. A package test bundle on the iOS simulator runs
/// without a host app, so it has no Keychain access group and every call fails with
/// `errSecMissingEntitlement`. The macOS login keychain needs no entitlement.
enum KeychainAvailability {
    static let isAvailable: Bool = {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "PassportKitTests.probe.\(UUID())",
            kSecAttrAccount as String: "probe",
        ]
        var item = query
        item[kSecValueData as String] = Data([0])
        let status = SecItemAdd(item as CFDictionary, nil)
        SecItemDelete(query as CFDictionary)
        return status == errSecSuccess
    }()
}
