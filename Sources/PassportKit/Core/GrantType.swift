import Foundation

/// An OAuth grant type identifier (`grant_type` parameter). An open set: extension grants are valid.
public struct GrantType: RawRepresentable, Sendable, Hashable, Codable {
    /// The `grant_type` value.
    public let rawValue: String

    /// Creates a grant type from its `grant_type` value.
    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    /// `authorization_code` (RFC 6749 §4.1.3).
    public static let authorizationCode = GrantType(rawValue: "authorization_code")
    /// `refresh_token` (RFC 6749 §6).
    public static let refreshToken = GrantType(rawValue: "refresh_token")
    /// `urn:ietf:params:oauth:grant-type:device_code` (RFC 8628 §3.4).
    public static let deviceCode = GrantType(rawValue: "urn:ietf:params:oauth:grant-type:device_code")
    /// `urn:ietf:params:oauth:grant-type:token-exchange` (RFC 8693 §2.1).
    public static let tokenExchange = GrantType(rawValue: "urn:ietf:params:oauth:grant-type:token-exchange")
    /// `client_credentials` (RFC 6749 §4.4.2).
    public static let clientCredentials = GrantType(rawValue: "client_credentials")

    /// Decodes the plain string value.
    public init(from decoder: any Decoder) throws {
        rawValue = try decoder.singleValueContainer().decode(String.self)
    }

    /// Encodes the plain string value.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}
