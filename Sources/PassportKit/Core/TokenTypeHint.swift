/// The `token_type_hint` of a revocation request (RFC 7009 §2.1).
public enum TokenTypeHint: String, Sendable {
    /// `access_token`
    case accessToken = "access_token"
    /// `refresh_token`
    case refreshToken = "refresh_token"
}
