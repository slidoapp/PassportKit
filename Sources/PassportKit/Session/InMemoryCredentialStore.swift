/// A ``CredentialStore`` that keeps credentials in memory: for tests, previews and short-lived processes.
public actor InMemoryCredentialStore: CredentialStore {
    private var credentials: [CredentialAccount: Credential]
    private var failingSaves = 0

    /// Creates a store, optionally with credentials already in it.
    public init(credentials: [CredentialAccount: Credential] = [:]) {
        self.credentials = credentials
    }

    /// Makes the next `count` calls to ``save(_:for:)`` throw ``PassportError/Code-swift.struct/storageFailure``.
    public func failNextSaves(_ count: Int = 1) {
        failingSaves = count
    }

    /// The stored credential, or `nil`.
    public func load(_ account: CredentialAccount) -> Credential? {
        credentials[account]
    }

    /// Stores `credential`, unless a failure was injected with ``failNextSaves(_:)``.
    public func save(_ credential: Credential, for account: CredentialAccount) throws {
        if failingSaves > 0 {
            failingSaves -= 1
            throw PassportError(.storageFailure, detail: "Saving the credential failed.")
        }
        credentials[account] = credential
    }

    /// Removes the stored credential.
    public func delete(_ account: CredentialAccount) {
        credentials[account] = nil
    }
}
