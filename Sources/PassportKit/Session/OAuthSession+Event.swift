extension OAuthSession {
    /// Why a session ended.
    ///
    /// Cases may be added in a minor release: the enumeration is not frozen, so a `switch` over it needs a `default`.
    public enum SignOutReason: Sendable, Hashable {
        /// ``OAuthSession/signOut(revoke:)`` or ``OAuthSession/beginSignOut(revoke:)`` was called.
        case userInitiated
        /// The authorization server rejected the refresh token (`invalid_grant`, RFC 6749 §5.2).
        case refreshTokenRejected
        /// The access token of a grant that issued no refresh token expired, so the session cannot continue.
        case expiredWithoutRefreshToken
    }

    /// Something that happened to the session, delivered through ``OAuthSession/events``.
    ///
    /// Cases may be added in a minor release: the enumeration is not frozen, so a `switch` over it needs a `default`.
    public enum Event: Sendable, Hashable {
        /// A credential was adopted by ``OAuthSession/signIn(with:requestedScope:)`` or
        /// ``OAuthSession/signIn(refreshToken:grantedScope:idToken:)``, or restored by ``OAuthSession/restore()``.
        case signedIn
        /// The session obtained a new access token for `target` and the acceptance policy accepted it.
        ///
        /// The token comes from a refresh grant (RFC 6749 §6) or, for a target with the token exchange derivation,
        /// a token exchange (RFC 8693 §2.1). The session caches it when its lifetime is known; a token without a
        /// known lifetime goes only to the callers that asked for it. The access token adopted by a sign-in and the
        /// result of ``OAuthSession/exchangeRefreshToken(audiences:resources:scope:requestedTokenType:)`` do not
        /// emit this event.
        case accessTokenUpdated(target: TokenTarget)
        /// A token for `target` was issued but rejected by the acceptance policy. The session is intact.
        case tokenRejected(target: TokenTarget, grantedScope: ScopeSet?)
        /// The credential could not be saved or deleted. It is kept in memory, so the session continues.
        case storageFailed
        /// The session ended; the credential is gone.
        case signedOut(reason: SignOutReason)
    }

    /// What a sign-out did: the result of ``OAuthSession/signOut(revoke:)`` and of
    /// ``OAuthSession/PendingSignOut/result`` after ``OAuthSession/beginSignOut(revoke:)``.
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
}
