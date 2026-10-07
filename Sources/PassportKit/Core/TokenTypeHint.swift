/// The `token_type_hint` of a revocation request (RFC 7009 §2.1). An open set: the IANA registry can grow
/// (RFC 7009 §4.1.2).
public struct TokenTypeHint: RawRepresentable, Sendable, Hashable {
    /// The `token_type_hint` value.
    public let rawValue: String

    /// Creates a hint from its `token_type_hint` value.
    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    /// `access_token`
    public static let accessToken = TokenTypeHint(rawValue: "access_token")
    /// `refresh_token`
    public static let refreshToken = TokenTypeHint(rawValue: "refresh_token")
}
