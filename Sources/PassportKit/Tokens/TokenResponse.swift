import Foundation

/// A successful token endpoint response (RFC 6749 §5.1, RFC 8693 §2.2.1).
///
/// Descriptions and reflection show which members are present, never token values or the
/// values of ``additionalFields``.
public struct TokenResponse: Sendable, Hashable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    /// The issued token (`access_token`).
    ///
    /// For every grant except a token exchange, this is an access token. A token exchange response carries the
    /// issued token in this member whatever its type, and ``issuedTokenType`` names the type (RFC 8693 §2.2.1).
    /// ``OAuthSession/exchangeRefreshToken(audiences:resources:scope:requestedTokenType:)`` asks for a refresh
    /// token by default, so its response holds a refresh token here.
    public var accessToken: Secret
    /// The token type (`token_type`), for example `Bearer`. Compare case-insensitively.
    ///
    /// When a token exchange issued something other than an access token and the response has no `token_type`,
    /// the value is `N_A` (RFC 8693 §2.2.1).
    public var tokenType: String
    /// The lifetime from `expires_in`, or `nil` when the server omitted it.
    public var expiresIn: Duration?
    /// The refresh token, when issued or rotated.
    public var refreshToken: Secret?
    /// The ID token, when issued.
    public var idToken: Secret?
    /// The `scope` as returned; `nil` when omitted. See ``grantedScope(requested:)``.
    public var scope: ScopeSet?
    /// The type of the token in ``accessToken``, from the `issued_token_type` of a token exchange response
    /// (RFC 8693 §2.2.1). A token exchange response always has it; other grants usually leave it `nil`.
    public var issuedTokenType: TokenTypeIdentifier?
    /// Every other member of the response, preserved without interpretation.
    public var additionalFields: [String: JSONValue]

    /// Creates a response.
    public init(
        accessToken: Secret,
        tokenType: String,
        expiresIn: Duration? = nil,
        refreshToken: Secret? = nil,
        idToken: Secret? = nil,
        scope: ScopeSet? = nil,
        issuedTokenType: TokenTypeIdentifier? = nil,
        additionalFields: [String: JSONValue] = [:]
    ) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.scope = scope
        self.issuedTokenType = issuedTokenType
        self.additionalFields = additionalFields
    }

    /// Whether ``tokenType`` is `Bearer`, compared case-insensitively (RFC 6749 §7.1, RFC 9110 §11.1).
    var isBearer: Bool {
        AuthenticationScheme.isBearer(tokenType)
    }

    /// The scope this token is valid for: the response `scope` when present, otherwise `requested`
    /// (RFC 6749 §5.1). A narrower scope than requested is not an error by itself (RFC 6749 §3.3).
    public func grantedScope(requested: ScopeSet?) -> ScopeSet? {
        scope ?? requested
    }

    /// A summary naming present members only.
    public var description: String {
        var parts = ["tokenType: \(tokenType)"]
        if let expiresIn { parts.append("expiresIn: \(expiresIn)") }
        if refreshToken != nil { parts.append("refreshToken: <redacted>") }
        if idToken != nil { parts.append("idToken: <redacted>") }
        if let scope { parts.append("scope: \(scope)") }
        if let issuedTokenType { parts.append("issuedTokenType: \(issuedTokenType.rawValue)") }
        if !additionalFields.isEmpty { parts.append("additionalFields: \(additionalFields.keys.sorted())") }
        return "TokenResponse(accessToken: <redacted>, \(parts.joined(separator: ", ")))"
    }

    /// Same as ``description``.
    public var debugDescription: String { description }

    /// A mirror exposing the summary only, so reflection cannot reach `additionalFields` values.
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}
