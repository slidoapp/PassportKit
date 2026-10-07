import Foundation

/// A successful token endpoint response (RFC 6749 §5.1, RFC 8693 §2.2.1).
///
/// Descriptions and reflection show which members are present, never token values or the
/// values of ``additionalFields``.
public struct TokenResponse: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The access token (`access_token`).
    public var accessToken: Secret
    /// The token type (`token_type`), for example `Bearer`. Compare case-insensitively, see ``isBearer``.
    public var tokenType: String
    /// The lifetime from `expires_in`, or `nil` when the server omitted it.
    public var expiresIn: Duration?
    /// The refresh token, when issued or rotated.
    public var refreshToken: Secret?
    /// The ID token, when issued.
    public var idToken: Secret?
    /// The `scope` as returned; `nil` when omitted. See ``grantedScope(requested:)``.
    public var scope: ScopeSet?
    /// The `issued_token_type` of a token exchange response (RFC 8693 §2.2.1).
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
    public var isBearer: Bool {
        tokenType.lowercased() == "bearer"
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
