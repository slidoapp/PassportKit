#if canImport(Security)
    import Dispatch
    import Foundation
    import PassportKit
    import Security

    /// A `CredentialStore` that keeps credentials as generic password items in the Keychain.
    ///
    /// The item's service and account are the `CredentialAccount`'s `service` and `account`; the library has
    /// no defaults for either. The payload is the versioned JSON of `CredentialCoding`. Items are never
    /// synchronizable: a refresh token is a bearer secret for one device and must not travel through iCloud
    /// Keychain, so `kSecAttrSynchronizable` is always `false` and there is no option to change it.
    ///
    /// Keychain calls block, so each runs on a private serial queue and the caller's executor is not held.
    /// The queue also serializes this store's own writes; ``save(_:for:)`` still tolerates another process
    /// creating the item first.
    ///
    /// Keychain access is a security boundary of the app, not of the library: an access group needs the
    /// matching entitlement, and without one the Keychain answers `errSecMissingEntitlement`, reported as
    /// `PassportError.Code.storageFailure`.
    public final class KeychainCredentialStore: CredentialStore {
        /// When the Keychain releases an item to the app (`kSecAttrAccessible`).
        ///
        /// The `…ThisDeviceOnly` classes keep the item out of backups and device migration. Prefer them for
        /// refresh tokens. On macOS the setting only applies with `useDataProtectionKeychain`, because the
        /// file-based keychain has no accessibility classes.
        public enum Accessibility: Sendable, Hashable {
            /// Readable while the device is unlocked.
            case whenUnlocked
            /// Readable from the first unlock after boot until the next restart.
            case afterFirstUnlock
            /// Like ``whenUnlocked``, never leaves the device.
            case whenUnlockedThisDeviceOnly
            /// Like ``afterFirstUnlock``, never leaves the device. Suits background refresh.
            case afterFirstUnlockThisDeviceOnly
            /// Readable while unlocked and only when a device passcode is set; never leaves the device.
            case whenPasscodeSetThisDeviceOnly

            var value: CFString {
                switch self {
                case .whenUnlocked: kSecAttrAccessibleWhenUnlocked
                case .afterFirstUnlock: kSecAttrAccessibleAfterFirstUnlock
                case .whenUnlockedThisDeviceOnly: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
                case .afterFirstUnlockThisDeviceOnly: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                case .whenPasscodeSetThisDeviceOnly: kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
                }
            }
        }

        private let accessGroup: String?
        private let accessibility: Accessibility
        private let usesDataProtection: Bool
        private let decodeLegacy: (@Sendable (Data) -> Credential?)?
        private let queue = DispatchQueue(label: "PassportKit.KeychainCredentialStore")

        /// Creates a store.
        ///
        /// - Parameters:
        ///   - accessGroup: The Keychain access group, to share credentials between apps of one team. `nil`
        ///     uses the app's default group.
        ///   - accessibility: When items become readable. Applied when an item is created and again on every
        ///     update.
        ///   - useDataProtectionKeychain: On macOS, use the data protection keychain
        ///     (`kSecUseDataProtectionKeychain`) instead of the file-based login keychain. It needs a signed
        ///     app with a keychain entitlement. Ignored on other platforms, where it is the only keychain.
        ///   - decodeLegacy: The migration hook. When a stored payload is not a record `CredentialCoding`
        ///     reads, the hook gets the raw bytes; a credential it returns is used and written back in the
        ///     current format (a failed write-back is ignored and retried by the next ``load(_:)``). Return
        ///     `nil` for data it does not recognise, which then fails as a malformed record. The hook runs on
        ///     the store's private queue and must not block.
        public init(
            accessGroup: String? = nil,
            accessibility: Accessibility = .afterFirstUnlockThisDeviceOnly,
            useDataProtectionKeychain: Bool = false,
            decodeLegacy: (@Sendable (Data) -> Credential?)? = nil
        ) {
            self.accessGroup = accessGroup
            self.accessibility = accessibility
            self.usesDataProtection = useDataProtectionKeychain
            self.decodeLegacy = decodeLegacy
        }

        /// The stored credential, or `nil` when the item does not exist.
        ///
        /// - Throws: `PassportError` with code `PassportError.Code.storageFailure`: for a
        ///   payload that cannot be decoded, with recovery `PassportError.Recovery.retryLater(after:)` while
        ///   the device is locked (`errSecInteractionNotAllowed`), and for any other Keychain status.
        public func load(_ account: CredentialAccount) async throws -> Credential? {
            try await perform { try self.loadSynchronously(account) }
        }

        /// Stores `credential`, updating the existing item in place or creating it.
        public func save(_ credential: Credential, for account: CredentialAccount) async throws {
            let data = try CredentialCoding.encode(credential)
            try await perform { try self.saveSynchronously(data, for: account) }
        }

        /// Removes the item. A missing item is not an error.
        public func delete(_ account: CredentialAccount) async throws {
            try await perform {
                let status = SecItemDelete(self.query(for: account) as CFDictionary)
                guard status == errSecSuccess || status == errSecItemNotFound else { throw Self.failure(status) }
            }
        }

        private func perform<Value: Sendable>(_ work: @escaping @Sendable () throws -> Value) async throws -> Value {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                queue.async { continuation.resume(with: Result(catching: work)) }
            }
        }

        private func loadSynchronously(_ account: CredentialAccount) throws -> Credential? {
            var search = query(for: account)
            search[kSecReturnData as String] = true
            search[kSecMatchLimit as String] = kSecMatchLimitOne
            var result: CFTypeRef?
            let status = SecItemCopyMatching(search as CFDictionary, &result)
            if status == errSecItemNotFound { return nil }
            guard status == errSecSuccess, let data = result as? Data else { throw Self.failure(status) }
            do {
                return try CredentialCoding.decode(data)
            } catch {
                guard let credential = decodeLegacy?(data) else { throw error }
                if let current = try? CredentialCoding.encode(credential) {
                    try? saveSynchronously(current, for: account)
                }
                return credential
            }
        }

        private func saveSynchronously(_ data: Data, for account: CredentialAccount) throws {
            var changes: [String: Any] = [kSecValueData as String: data]
            if appliesAccessibility { changes[kSecAttrAccessible as String] = accessibility.value }
            var status = SecItemUpdate(query(for: account) as CFDictionary, changes as CFDictionary)
            if status == errSecItemNotFound {
                status = SecItemAdd(query(for: account).merging(changes) { $1 } as CFDictionary, nil)
                if status == errSecDuplicateItem {
                    // Another process created the item between the update and the add.
                    status = SecItemUpdate(query(for: account) as CFDictionary, changes as CFDictionary)
                }
            }
            guard status == errSecSuccess else { throw Self.failure(status) }
        }

        private var appliesAccessibility: Bool {
            #if os(macOS)
                usesDataProtection
            #else
                true
            #endif
        }

        private func query(for account: CredentialAccount) -> [String: Any] {
            var query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: account.service,
                kSecAttrAccount as String: account.account,
                kSecAttrSynchronizable as String: false,
            ]
            if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
            #if os(macOS)
                if usesDataProtection { query[kSecUseDataProtectionKeychain as String] = true }
            #endif
            return query
        }

        /// The status is public information; no item data is involved.
        private static func failure(_ status: OSStatus) -> PassportError {
            let underlying = NSError(domain: NSOSStatusErrorDomain, code: Int(status))
            if status == errSecInteractionNotAllowed {
                return PassportError(
                    .storageFailure,
                    recovery: .retryLater(after: nil),
                    errorDescription: "The Keychain is not available while the device is locked.",
                    underlying: underlying
                )
            }
            return PassportError(
                .storageFailure,
                errorDescription: "The Keychain operation failed with status \(status).",
                underlying: underlying
            )
        }
    }
#endif
