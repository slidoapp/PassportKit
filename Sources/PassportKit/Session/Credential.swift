import Foundation

/// The root grant of a session: what is persisted between launches. Access tokens are never part of it.
///
/// Descriptions and reflection never show token values or the values of ``additionalFields``.
public struct Credential: Sendable, Codable, Hashable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    /// The client the grant was issued to. A stored credential for another client is ignored.
    public var clientID: String
    /// The issuer the grant came from, when the client knows it.
    public var issuer: URL?
    /// The refresh token, the root of every derived token. `nil` when the grant issued none.
    public var refreshToken: Secret?
    /// The ID token, when one was issued.
    public var idToken: Secret?
    /// The scope of the grant.
    public var grantedScope: ScopeSet?
    /// When the credential was last written.
    public var updatedAt: Date
    /// Application data stored with the credential, preserved without interpretation.
    public var additionalFields: [String: JSONValue]

    /// Creates a credential.
    public init(
        clientID: String,
        issuer: URL? = nil,
        refreshToken: Secret? = nil,
        idToken: Secret? = nil,
        grantedScope: ScopeSet? = nil,
        updatedAt: Date,
        additionalFields: [String: JSONValue] = [:]
    ) {
        self.clientID = clientID
        self.issuer = issuer
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.grantedScope = grantedScope
        self.updatedAt = updatedAt
        self.additionalFields = additionalFields
    }

    /// A summary that names present members only.
    public var description: String {
        var parts = ["clientID: \(clientID)"]
        if let issuer { parts.append("issuer: \(issuer.absoluteString)") }
        if refreshToken != nil { parts.append("refreshToken: <redacted>") }
        if idToken != nil { parts.append("idToken: <redacted>") }
        if let grantedScope { parts.append("grantedScope: \(grantedScope)") }
        if !additionalFields.isEmpty { parts.append("additionalFields: \(additionalFields.keys.sorted())") }
        return "Credential(\(parts.joined(separator: ", ")))"
    }

    /// Same as ``description``.
    public var debugDescription: String { description }

    /// A mirror exposing the summary only.
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}

/// Where a credential lives: a service and an account name, like a Keychain item. The library has no defaults.
public struct CredentialAccount: Sendable, Hashable {
    /// The service or namespace, for example an application identifier.
    public var service: String
    /// The account name within the service.
    public var account: String

    /// Creates an account.
    public init(service: String, account: String) {
        self.service = service
        self.account = account
    }
}

/// Persistence for the root credential. Implementations must be safe to call concurrently.
///
/// Implementations should throw ``PassportError`` with code ``PassportError/Code-swift.struct/storageFailure``;
/// the manager wraps any other error. `load` returns `nil` for "not found" and throws for every other failure.
public protocol CredentialStore: Sendable {
    /// The stored credential, or `nil` when there is none.
    func load(_ account: CredentialAccount) async throws -> Credential?
    /// Stores `credential`, replacing any previous one.
    func save(_ credential: Credential, for account: CredentialAccount) async throws
    /// Removes the stored credential. Deleting a missing credential is not an error.
    func delete(_ account: CredentialAccount) async throws
}
