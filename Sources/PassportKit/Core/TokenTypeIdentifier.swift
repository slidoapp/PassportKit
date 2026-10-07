import Foundation

/// A token type identifier URI (RFC 8693 §3). An open set.
public struct TokenTypeIdentifier: RawRepresentable, Sendable, Hashable, Codable {
    /// The identifier URI.
    public let rawValue: String

    /// Creates an identifier from its URI.
    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    /// `urn:ietf:params:oauth:token-type:access_token` (RFC 8693 §3).
    public static let accessToken = TokenTypeIdentifier(rawValue: "urn:ietf:params:oauth:token-type:access_token")
    /// `urn:ietf:params:oauth:token-type:refresh_token` (RFC 8693 §3).
    public static let refreshToken = TokenTypeIdentifier(rawValue: "urn:ietf:params:oauth:token-type:refresh_token")
    /// `urn:ietf:params:oauth:token-type:id_token` (RFC 8693 §3).
    public static let idToken = TokenTypeIdentifier(rawValue: "urn:ietf:params:oauth:token-type:id_token")
    /// `urn:ietf:params:oauth:token-type:jwt` (RFC 8693 §3).
    public static let jwt = TokenTypeIdentifier(rawValue: "urn:ietf:params:oauth:token-type:jwt")

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
