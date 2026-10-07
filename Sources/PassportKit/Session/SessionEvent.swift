/// Why a session ended.
public enum SignOutReason: Sendable, Hashable {
    /// ``TokenManager/signOut(revoke:)`` was called.
    case userInitiated
    /// The authorization server rejected the refresh token (`invalid_grant`, RFC 6749 §5.2).
    case refreshTokenRejected
}

/// Something that happened to the session, delivered through ``TokenManager/events``.
public enum SessionEvent: Sendable, Equatable {
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

/// What ``TokenManager/signOut(revoke:)`` did.
public struct SignOutResult: Sendable, Equatable {
    /// The outcome of revoking the refresh token (RFC 7009).
    public enum Revocation: Sendable, Equatable {
        /// Not attempted: not requested, no refresh token, or no revocation endpoint configured.
        case skipped
        /// The server accepted the revocation.
        case revoked
        /// The server or the network refused. The token may still be valid at the server.
        case failed(PassportError)
        /// The request did not finish within the time box. It may still complete in the background.
        case timedOut
    }

    /// Whether the stored credential was deleted. The in-memory session is always cleared.
    public var isStoredCredentialDeleted: Bool
    /// What happened to the refresh token at the server.
    public var revocation: Revocation

    /// Creates a result.
    public init(isStoredCredentialDeleted: Bool, revocation: Revocation) {
        self.isStoredCredentialDeleted = isStoredCredentialDeleted
        self.revocation = revocation
    }
}
