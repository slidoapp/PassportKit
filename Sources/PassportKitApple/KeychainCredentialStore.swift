#if canImport(Security)
    import Dispatch
    import Foundation
    import Logging
    import PassportKit
    import Security
    import SwiftKeychain

    /// A `CredentialStore` that keeps credentials as generic password items in the Keychain.
    ///
    /// The item's service and account are the `CredentialAccount`'s `service` and `account`; the library has
    /// no defaults for either. Items are written through SwiftKeychain: the payload is the versioned JSON of
    /// `CredentialCoding`, kept as one value inside SwiftKeychain's archived dictionary. Items are never
    /// synchronizable: a refresh token is a bearer secret for one device and must not travel through iCloud
    /// Keychain, so `kSecAttrSynchronizable` is always `false` and there is no option to change it.
    ///
    /// Keychain calls block, so each runs on a private serial queue and the caller's executor is not held.
    /// The queue also serializes this store's own writes.
    ///
    /// Known issue: when an item already exists, SwiftKeychain replaces it by deleting it and adding it again
    /// instead of updating it. If the second step fails (device locked, denied prompt, entitlement problem) or
    /// the process dies in between, the stored credential is lost and the user has to sign in again; two
    /// stores writing the same item at once can fail the same way. See ADR 0009.
    ///
    /// Keychain access is a security boundary of the app, not of the library: an access group needs the
    /// matching entitlement, and without one the Keychain answers `errSecMissingEntitlement`, reported as
    /// `PassportError.Code.storageFailure`.
    public final class KeychainCredentialStore: CredentialStore {
        /// When the Keychain releases an item to the app (`kSecAttrAccessible`).
        ///
        /// The `…ThisDeviceOnly` classes keep the item out of backups and device migration. Prefer them for
        /// refresh tokens. The store uses the login keychain on macOS: SwiftKeychain cannot target the data
        /// protection keychain.
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
        private let decodeLegacy: (@Sendable (Data) -> Credential?)?
        private let logger: Logger
        private let queue = DispatchQueue(label: "PassportKit.KeychainCredentialStore")

        /// The key of the credential JSON inside the item's archived dictionary.
        private static let payloadKey = "credential"

        /// Creates a store.
        ///
        /// - Parameters:
        ///   - accessGroup: The Keychain access group, to share credentials between apps of one team. `nil`
        ///     uses the app's default group.
        ///   - accessibility: When items become readable. Applied when an item is created, and part of the
        ///     item's identity: an item stored with another class is not found.
        ///   - decodeLegacy: The migration hook. When a stored payload is not a record `CredentialCoding`
        ///     reads, the hook gets the payload bytes (the raw item data, or the JSON inside SwiftKeychain's
        ///     envelope); a credential it returns is used and written back in the current format (a failed
        ///     write-back is ignored and retried by the next ``load(_:)``). Return `nil` for data it does not
        ///     recognise, which then fails as a malformed record. The hook runs on the store's private queue
        ///     and must not block.
        ///   - logger: Receives storage failures and migrations, never credentials.
        public init(
            accessGroup: String? = nil,
            accessibility: Accessibility = .afterFirstUnlockThisDeviceOnly,
            decodeLegacy: (@Sendable (Data) -> Credential?)? = nil,
            logger: Logger = Logger(label: "PassportKit")
        ) {
            self.accessGroup = accessGroup
            self.accessibility = accessibility
            self.decodeLegacy = decodeLegacy
            self.logger = logger
        }

        public func load(_ account: CredentialAccount) async throws -> Credential? {
            try await perform { try self.loadSynchronously(account) }
        }

        public func save(_ credential: Credential, for account: CredentialAccount) async throws {
            let data = try CredentialCoding.encode(credential)
            try await perform { try self.saveSynchronously(data, for: account) }
        }

        public func delete(_ account: CredentialAccount) async throws {
            try await perform {
                do {
                    try self.item(for: account).removeFromKeychain()
                } catch  where Self.isNotFound(error) {
                    return
                } catch {
                    throw self.failure(error, operation: "delete")
                }
            }
        }

        private func perform<Value: Sendable>(_ work: @escaping @Sendable () throws -> Value) async throws -> Value {
            try Task.checkCancellation()
            return try await withCheckedThrowingContinuation { continuation in
                queue.async { continuation.resume(with: Result(catching: work)) }
            }
        }

        private func loadSynchronously(_ account: CredentialAccount) throws -> Credential? {
            var item = item(for: account)
            let payload: Data
            do {
                _ = try item.fetchFromKeychain()
                guard let stored = item.data[Self.payloadKey] as? Data else { return try migrateRaw(account) }
                payload = stored
            } catch  where Self.isNotFound(error) {
                return nil
            } catch  where (error as NSError).domain != Self.keychainErrorDomain {
                // The item is not a SwiftKeychain envelope: a record this library or another wrote directly.
                return try migrateRaw(account)
            } catch {
                throw failure(error, operation: "load")
            }
            do {
                return try CredentialCoding.decode(payload)
            } catch {
                return try migrate(payload, account: account, original: error)
            }
        }

        /// Reads the item as raw bytes, for payloads that are not in SwiftKeychain's envelope.
        private func migrateRaw(_ account: CredentialAccount) throws -> Credential? {
            var query = item(for: account).attributes
            query[String(kSecReturnData)] = true
            query[String(kSecReturnAttributes)] = true
            if let accessGroup { query[String(kSecAttrAccessGroup)] = accessGroup }
            let raw: Data?
            do {
                raw = try Keychain().fetchItemWithAttributes(query)?[String(kSecValueData)] as? Data
            } catch  where Self.isNotFound(error) {
                return nil
            } catch {
                throw failure(error, operation: "load")
            }
            guard let raw else { return nil }
            if let credential = try? CredentialCoding.decode(raw) {
                rewrite(credential, account: account)
                return credential
            }
            return try migrate(raw, account: account, original: nil)
        }

        private func migrate(_ payload: Data, account: CredentialAccount, original: (any Error)?) throws -> Credential {
            guard let credential = decodeLegacy?(payload) else {
                logger.warning("The stored credential could not be decoded")
                throw original ?? PassportError(.storageFailure, detail: "The stored credential is malformed.")
            }
            logger.notice("Migrated a legacy stored credential")
            rewrite(credential, account: account)
            return credential
        }

        private func rewrite(_ credential: Credential, account: CredentialAccount) {
            if let current = try? CredentialCoding.encode(credential) {
                try? saveSynchronously(current, for: account)
            }
        }

        private func saveSynchronously(_ data: Data, for account: CredentialAccount) throws {
            var item = item(for: account)
            item.data = [Self.payloadKey: data]
            do {
                // Known issue: on `errSecDuplicateItem` SwiftKeychain deletes the existing item and adds it
                // again (Keychain.insertItemWithAttributes). If the second step fails, or the process dies in
                // between, the credential is lost, and with refresh token rotation the replaced token is
                // already invalid. The payload is also archived with `try?`, so an encoding failure would
                // store no data. Planned fix: an upstream change to update first (ADR 0009).
                try item.saveInKeychain()
            } catch {
                throw failure(error, operation: "save")
            }
        }

        private func item(for account: CredentialAccount) -> CredentialItem {
            CredentialItem(
                serviceName: account.service, accountName: account.account, accessGroup: accessGroup,
                accessMode: String(accessibility.value), storedClasses: [NSData.self, NSString.self])
        }

        private static let keychainErrorDomain = "swift.keychain.error"

        private static func isNotFound(_ error: any Error) -> Bool {
            let error = error as NSError
            return error.domain == keychainErrorDomain && error.code == Int(errSecItemNotFound)
        }

        private func failure(_ error: any Error, operation: String) -> PassportError {
            let nsError = error as NSError
            let status = nsError.domain == Self.keychainErrorDomain ? OSStatus(nsError.code) : errSecDecode
            let level: Logger.Level = status == errSecInteractionNotAllowed ? .notice : .warning
            logger.log(
                level: level, "A Keychain operation failed",
                metadata: [LogKey.operation: "\(operation)", LogKey.status: "\(status)"])
            return Self.failure(status)
        }

        static func failure(_ status: OSStatus) -> PassportError {
            let underlying = NSError(domain: NSOSStatusErrorDomain, code: Int(status))
            if status == errSecInteractionNotAllowed {
                return PassportError(
                    .storageFailure,
                    recovery: .retryLater(after: nil),
                    detail: "The Keychain is not available while the device is locked.",
                    underlying: underlying
                )
            }
            return PassportError(
                .storageFailure,
                detail: "The Keychain operation failed with status \(status).",
                underlying: underlying
            )
        }
    }

    /// The item SwiftKeychain reads and writes: one generic password with one data value.
    private struct CredentialItem: KeychainGenericPasswordType {
        let serviceName: String
        let accountName: String
        let accessGroup: String?
        let accessMode: String
        let storedClasses: [AnyClass]
        var data = KeychainData()
        var dataToStore: KeychainData { data }
    }
#endif
