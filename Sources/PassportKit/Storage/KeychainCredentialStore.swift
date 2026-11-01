import Dispatch
import Foundation
import Logging
import Security
import SwiftKeychain

/// A `CredentialStore` that keeps credentials as generic password items in the Keychain.
///
/// The item's service and account are the `CredentialAccount`'s `service` and `account`; the library has
/// no defaults for either. The payload is the versioned JSON of `CredentialCoding`, kept as one value inside
/// SwiftKeychain's archived dictionary; the store makes the Keychain calls itself, matching the item by
/// class, service, account and access group. Items are never
/// synchronizable: a refresh token is a bearer secret for one device and must not travel through iCloud
/// Keychain. The store sets `kSecAttrSynchronizable` to `false` when it adds, fetches and deletes an item,
/// and there is no option to change it.
///
/// ## Platform differences
///
/// On iOS the items live in the data protection keychain, which enforces ``Accessibility`` and the access
/// group. On macOS the store uses the file-based login keychain, because SwiftKeychain cannot target the
/// data protection keychain, and there neither is enforced: an item is readable whenever the login keychain
/// is unlocked, whatever its accessibility class, and the access group does not partition items. Access to
/// an item is then decided by the keychain's own access control for the app that created it. Do not rely on
/// ``Accessibility`` or `accessGroup` to protect or share a credential on macOS.
///
/// Keychain calls block, so each runs on a private serial queue and the caller's executor is not held.
/// The queue also serializes this store's own writes.
///
/// A save updates an existing item in place (`SecItemUpdate`) and adds one only when none exists, so a failed
/// save leaves the previous credential stored, and stores that write the same item at once do not lose it.
///
/// Keychain access is a security boundary of the app, not of the library: an access group needs the
/// matching entitlement, and without one the Keychain answers `errSecMissingEntitlement`, reported as
/// `PassportError.Code.storageFailure`.
public final class KeychainCredentialStore: CredentialStore {
    /// When the Keychain releases an item to the app (`kSecAttrAccessible`).
    ///
    /// The `…ThisDeviceOnly` classes keep the item out of backups and device migration. Prefer them for
    /// refresh tokens. The class is enforced on iOS only: the login keychain that the store uses on macOS
    /// does not enforce it, because SwiftKeychain cannot target the data protection keychain.
    ///
    /// Cases may be added in a minor release, as the Keychain gains classes: the enumeration is not frozen, so a
    /// `switch` over it needs a `default`.
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
    private let logger: Logger
    private let queue = DispatchQueue(label: "PassportKit.KeychainCredentialStore")

    /// The key of the credential JSON inside the item's archived dictionary.
    private static let payloadKey = "credential"

    /// Creates a store.
    ///
    /// - Parameters:
    ///   - accessGroup: The Keychain access group, to share credentials between apps of one team. `nil`
    ///     adds new items to the app's default group but, as for any Keychain query without a group, loads,
    ///     replaces and deletes the item for `account` in whichever of the app's groups holds it. Apps that
    ///     share a group and use the same service and account in several groups should name the group.
    ///     Enforced on iOS only; the login keychain on macOS ignores it.
    ///   - accessibility: When items become readable. Not part of the item's identity: a save also moves an
    ///     item stored with another class to this one.
    ///   - logger: Receives storage failures, never credentials.
    public init(
        accessGroup: String? = nil,
        accessibility: Accessibility = .afterFirstUnlockThisDeviceOnly,
        logger: Logger = Logger(label: "PassportKit")
    ) {
        self.accessGroup = accessGroup
        self.accessibility = accessibility
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
                try self.keychain(for: account).removeItemWithAttributes([:])
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
            _ = try item.fetchFromKeychain(keychain(for: account))
            guard let stored = item.data[Self.payloadKey] as? Data else { throw Self.malformed }
            payload = stored
        } catch  where Self.isNotFound(error) {
            return nil
        } catch  where (error as NSError).domain != Self.keychainErrorDomain {
            // Not a SwiftKeychain envelope holding this library's record, whoever wrote it.
            logger.warning("The stored credential could not be decoded")
            throw Self.malformed
        } catch {
            throw failure(error, operation: "load")
        }
        do {
            return try CredentialCoding.decode(payload)
        } catch {
            logger.warning("The stored credential could not be decoded")
            throw error
        }
    }

    private static let malformed = PassportError(.storageFailure, detail: "The stored credential is malformed.")

    private func saveSynchronously(_ data: Data, for account: CredentialAccount) throws {
        var item = item(for: account)
        item.data = [Self.payloadKey: data]
        do {
            try item.saveInKeychain(keychain(for: account))
        } catch {
            throw failure(error, operation: "save")
        }
    }

    /// Matches the item by identity only, for load, save and delete. SwiftKeychain's own queries carry
    /// `kSecAttrAccessible`, so an item stored with another class would be neither found, replaced nor deleted.
    /// Without an access group the query names none, so on iOS it matches the item in any group the app can
    /// reach (see ``init(accessGroup:accessibility:logger:)``).
    func identityQuery(for account: CredentialAccount) -> KeychainAttributes {
        var query: KeychainAttributes = [
            String(kSecClass): String(kSecClassGenericPassword),
            String(kSecAttrService): account.service,
            String(kSecAttrAccount): account.account,
            String(kSecAttrSynchronizable): false,
        ]
        if let accessGroup { query[String(kSecAttrAccessGroup)] = accessGroup }
        return query
    }

    private func keychain(for account: CredentialAccount) -> CredentialKeychain {
        CredentialKeychain(identity: identityQuery(for: account), accessibility: String(accessibility.value))
    }

    private func item(for account: CredentialAccount) -> CredentialItem {
        CredentialItem(
            serviceName: account.service, accountName: account.account, accessGroup: accessGroup,
            accessMode: String(accessibility.value), storedClasses: [NSData.self, NSString.self])
    }

    fileprivate static let keychainErrorDomain = "swift.keychain.error"

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

/// The Keychain calls of the store: SwiftKeychain's `Keychain`, except that every call matches the item by its
/// identity (``KeychainCredentialStore/identityQuery(for:)``) and a save updates the existing item in place.
///
/// SwiftKeychain replaces an existing item by deleting and adding it, so a failure in between would lose the
/// credential (ADR 0009). Its queries also carry `kSecAttrAccessible`, which the data protection keychain
/// matches on, so after an app changed ``KeychainCredentialStore/Accessibility`` the old item would be neither
/// found nor replaced.
private struct CredentialKeychain: KeychainServiceType {
    /// Class, service, account, `kSecAttrSynchronizable: false` and the access group, if one is set.
    let identity: KeychainAttributes
    /// The `kSecAttrAccessible` value the item gets, whether it is added or updated.
    let accessibility: String

    func insertItemWithAttributes(_ attributes: KeychainAttributes) throws {
        // SwiftKeychain archives the payload with `try?`; without data there is nothing to store.
        guard let data = attributes[String(kSecValueData)] else { throw Self.error(errSecParam) }
        // The attributes to change must not repeat `kSecClass` or anything else of the query.
        let changes: KeychainAttributes = [String(kSecValueData): data, String(kSecAttrAccessible): accessibility]
        var status = SecItemUpdate(identity as CFDictionary, changes as CFDictionary)
        if status == errSecItemNotFound {
            status = SecItemAdd(attributes as CFDictionary, nil)
            // Another store added the item since the update looked: update that one.
            if status == errSecDuplicateItem {
                status = SecItemUpdate(identity as CFDictionary, changes as CFDictionary)
            }
        }
        guard status == errSecSuccess else { throw Self.error(status) }
    }

    func removeItemWithAttributes(_ attributes: KeychainAttributes) throws {
        try Keychain().removeItemWithAttributes(identity)
    }

    func fetchItemWithAttributes(_ attributes: KeychainAttributes) throws -> KeychainItem? {
        var query = identity
        query[String(kSecReturnData)] = attributes[String(kSecReturnData)]
        query[String(kSecReturnAttributes)] = attributes[String(kSecReturnAttributes)]
        return try Keychain().fetchItemWithAttributes(query)
    }

    /// An error in SwiftKeychain's domain, which the store maps like SwiftKeychain's own.
    private static func error(_ status: OSStatus) -> NSError {
        NSError(domain: KeychainCredentialStore.keychainErrorDomain, code: Int(status))
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

    /// SwiftKeychain's attributes plus `kSecAttrSynchronizable: false`, so adding, fetching and
    /// deleting never involve an iCloud Keychain item. The rest repeats what its default
    /// implementation builds, which a type cannot call once it supplies its own.
    var attributes: KeychainAttributes {
        [
            String(kSecClass): String(kSecClassGenericPassword),
            String(kSecAttrAccessible): accessMode,
            String(kSecAttrService): serviceName,
            String(kSecAttrAccount): accountName,
            String(kSecAttrSynchronizable): false,
        ]
    }
}
