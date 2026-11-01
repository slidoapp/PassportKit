/// Why a session ended.
///
/// Cases may be added in a minor release: the enumeration is not frozen, so a `switch` over it needs a `default`.
public enum SignOutReason: Sendable, Hashable {
    /// ``TokenManager/signOut(revoke:)`` or ``TokenManager/beginSignOut(revoke:)`` was called.
    case userInitiated
    /// The authorization server rejected the refresh token (`invalid_grant`, RFC 6749 §5.2).
    case refreshTokenRejected
    /// The access token of a grant that issued no refresh token expired, so the session cannot continue.
    case expiredWithoutRefreshToken
}

/// Something that happened to the session, delivered through ``TokenManager/events``.
///
/// Cases may be added in a minor release: the enumeration is not frozen, so a `switch` over it needs a `default`.
public enum SessionEvent: Sendable, Hashable {
    /// A credential was adopted by ``TokenManager/signIn(with:requestedScope:)`` or restored by ``TokenManager/load()``.
    case signedIn
    /// A token for `target` was issued, accepted and cached.
    case refreshed(target: TokenTarget)
    /// A token for `target` was issued but rejected by the acceptance policy. The session is intact.
    case tokenRejected(target: TokenTarget, grantedScope: ScopeSet?)
    /// The credential could not be saved or deleted. It is kept in memory, so the session continues.
    case storageFailed
    /// The session ended; the credential is gone.
    case signedOut(reason: SignOutReason)
}

/// What a sign-out did: the result of ``TokenManager/signOut(revoke:)`` and of
/// ``PendingSignOut/result`` after ``TokenManager/beginSignOut(revoke:)``.
public struct SignOutResult: Sendable, Equatable {
    /// Whether the stored credential was deleted. The in-memory session is always cleared.
    public var isStoredCredentialDeleted: Bool
    /// What happened to the refresh token at the server.
    public var revocation: RevocationOutcome

    /// Creates a result.
    public init(isStoredCredentialDeleted: Bool, revocation: RevocationOutcome) {
        self.isStoredCredentialDeleted = isStoredCredentialDeleted
        self.revocation = revocation
    }
}
