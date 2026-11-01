/// What happened to a best-effort token revocation (RFC 7009 §2): at sign-out
/// (``SignOutResult/revocation``) or with ``OAuthClient/revokeBestEffort(_:typeHint:timeLimit:)``.
///
/// Revocation is a courtesy to the server: whatever the outcome, the token may still be valid (§2.2). Cases may be
/// added in a minor release: the enumeration is not frozen, so a `switch` over it needs a `default`.
public enum RevocationOutcome: Sendable, Equatable {
    /// Not attempted. At sign-out: revocation was not requested, the session had no refresh token, or no
    /// revocation endpoint is configured. For ``OAuthClient/revokeBestEffort(_:typeHint:timeLimit:)``: no
    /// revocation endpoint is configured.
    case skipped
    /// The server accepted the revocation (any 2xx, §2.2).
    case revoked
    /// The server or the network refused. The token may still be valid at the server.
    case failed(PassportError)
    /// The request did not finish within the time limit. It may still have reached the server.
    case timedOut
    /// The calling task was cancelled while it waited. At sign-out (``TokenManager/signOut(revoke:)`` or
    /// ``PendingSignOut/result``) the revocation continues in the background and may still succeed, and the
    /// session is cleared either way. For ``OAuthClient/revokeBestEffort(_:typeHint:timeLimit:)`` the request is
    /// cancelled; it may still have reached the server.
    case cancelled
}
