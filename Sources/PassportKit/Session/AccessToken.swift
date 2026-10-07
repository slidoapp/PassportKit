import Foundation

/// An access token issued for a ``TokenTarget``.
///
/// Descriptions and reflection never show the token value or the values of ``additionalFields``.
public struct AccessToken: Sendable, Hashable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    /// The token value. Send it as `Authorization: Bearer`; never log it.
    public var value: Secret
    /// The token type, for example `Bearer`. Compare case-insensitively.
    public var tokenType: String
    /// When the token expires, from `expires_in` or the configured default lifetime; `nil` when unknown.
    public var expiresAt: Date?
    /// The scope the token carries: the response `scope`, or the requested scope when omitted (RFC 6749 §5.1).
    public var grantedScope: ScopeSet?
    /// The target the token was issued for.
    public var target: TokenTarget
    /// Changes whenever the cached token for ``target`` changes. Pass the token to
    /// ``TokenManager/invalidate(_:)`` after a 401 and only this exact token is dropped.
    public internal(set) var generation: Int
    /// Every other member of the token response, preserved without interpretation.
    public var additionalFields: [String: JSONValue]

    package init(
        value: Secret,
        tokenType: String,
        expiresAt: Date? = nil,
        grantedScope: ScopeSet? = nil,
        target: TokenTarget = .default,
        generation: Int = 0,
        additionalFields: [String: JSONValue] = [:]
    ) {
        self.value = value
        self.tokenType = tokenType
        self.expiresAt = expiresAt
        self.grantedScope = grantedScope
        self.target = target
        self.generation = generation
        self.additionalFields = additionalFields
    }

    /// A summary that names present members only.
    public var description: String {
        var parts = ["tokenType: \(tokenType)"]
        if let expiresAt { parts.append("expiresAt: \(expiresAt)") }
        if let grantedScope { parts.append("grantedScope: \(grantedScope)") }
        parts.append("generation: \(generation)")
        return "AccessToken(value: <redacted>, \(parts.joined(separator: ", ")))"
    }

    /// Same as ``description``.
    public var debugDescription: String { description }

    /// A mirror exposing the summary only.
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}
