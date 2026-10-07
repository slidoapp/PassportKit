/// What a failed authorization server request was doing, which decides the ``PassportError/Recovery``.
enum ErrorResponseContext: Sendable, Hashable, CaseIterable {
    /// A refresh token grant (RFC 6749 §6). `invalid_grant` ends the session.
    case refreshGrant
    /// A token exchange whose subject is the refresh token (RFC 8693). `invalid_grant` ends the session.
    case exchangeWithRefreshToken
    /// A device authorization poll (RFC 8628 §3.4): `access_denied` is the user declining.
    case deviceAuthorizationPoll
    /// An authorization response from the redirect (RFC 6749 §4.1.2.1): `access_denied` is the user declining.
    case authorizationResponse
    /// Any other request: authorization code redemption, client credentials, extension grants, revocation.
    case other
}
