import Foundation

/// Authorization server metadata (RFC 8414 §2), as served at a well-known URL.
///
/// Metadata is a hint: PassportKit does not refuse a flow because a capability is not advertised
/// (specification §11). Members this type does not model are kept in ``additionalFields`` and survive
/// encoding. Coding keys are the RFC's snake_case member names.
public struct AuthorizationServerMetadata: Sendable, Codable, Hashable {
    /// `issuer` (RFC 8414 §2): required.
    public var issuer: URL
    /// `authorization_endpoint`.
    public var authorizationEndpoint: URL?
    /// `token_endpoint`.
    public var tokenEndpoint: URL?
    /// `device_authorization_endpoint` (RFC 8628 §4).
    public var deviceAuthorizationEndpoint: URL?
    /// `revocation_endpoint` (RFC 7009 §2).
    public var revocationEndpoint: URL?
    /// `code_challenge_methods_supported` (RFC 8414 §2).
    public var codeChallengeMethodsSupported: [String]?
    /// `grant_types_supported`.
    public var grantTypesSupported: [String]?
    /// `authorization_response_iss_parameter_supported` (RFC 9207 §3): when `true`, set
    /// ``ClientConfiguration/requiresIssuerInAuthorizationResponse``.
    public var authorizationResponseIssParameterSupported: Bool?
    /// Every other member, unchanged, for example vendor extensions.
    public var additionalFields: [String: JSONValue]

    /// Creates metadata.
    public init(
        issuer: URL,
        authorizationEndpoint: URL? = nil,
        tokenEndpoint: URL? = nil,
        deviceAuthorizationEndpoint: URL? = nil,
        revocationEndpoint: URL? = nil,
        codeChallengeMethodsSupported: [String]? = nil,
        grantTypesSupported: [String]? = nil,
        authorizationResponseIssParameterSupported: Bool? = nil,
        additionalFields: [String: JSONValue] = [:]
    ) {
        self.issuer = issuer
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint
        self.revocationEndpoint = revocationEndpoint
        self.codeChallengeMethodsSupported = codeChallengeMethodsSupported
        self.grantTypesSupported = grantTypesSupported
        self.authorizationResponseIssParameterSupported = authorizationResponseIssParameterSupported
        self.additionalFields = additionalFields
    }

    private struct Key: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init(_ name: String) { stringValue = name }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }

        static let issuer = Key("issuer")
        static let authorizationEndpoint = Key("authorization_endpoint")
        static let tokenEndpoint = Key("token_endpoint")
        static let deviceAuthorizationEndpoint = Key("device_authorization_endpoint")
        static let revocationEndpoint = Key("revocation_endpoint")
        static let codeChallengeMethodsSupported = Key("code_challenge_methods_supported")
        static let grantTypesSupported = Key("grant_types_supported")
        static let authorizationResponseIssParameterSupported = Key("authorization_response_iss_parameter_supported")

        static let known: Set<String> = [
            issuer, authorizationEndpoint, tokenEndpoint, deviceAuthorizationEndpoint, revocationEndpoint,
            codeChallengeMethodsSupported, grantTypesSupported, authorizationResponseIssParameterSupported,
        ].reduce(into: []) { $0.insert($1.stringValue) }
    }

    /// Decodes the known members and keeps the rest in ``additionalFields``.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: Key.self)
        issuer = try container.decode(URL.self, forKey: .issuer)
        authorizationEndpoint = try container.decodeIfPresent(URL.self, forKey: .authorizationEndpoint)
        tokenEndpoint = try container.decodeIfPresent(URL.self, forKey: .tokenEndpoint)
        deviceAuthorizationEndpoint = try container.decodeIfPresent(URL.self, forKey: .deviceAuthorizationEndpoint)
        revocationEndpoint = try container.decodeIfPresent(URL.self, forKey: .revocationEndpoint)
        codeChallengeMethodsSupported = try container.decodeIfPresent(
            [String].self, forKey: .codeChallengeMethodsSupported)
        grantTypesSupported = try container.decodeIfPresent([String].self, forKey: .grantTypesSupported)
        authorizationResponseIssParameterSupported = try container.decodeIfPresent(
            Bool.self, forKey: .authorizationResponseIssParameterSupported)
        additionalFields = [:]
        for key in container.allKeys where !Key.known.contains(key.stringValue) {
            additionalFields[key.stringValue] = try container.decode(JSONValue.self, forKey: key)
        }
    }

    /// Encodes the known members that are set, then ``additionalFields`` (a name that is also a known member is
    /// ignored there).
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: Key.self)
        try container.encode(issuer, forKey: .issuer)
        try container.encodeIfPresent(authorizationEndpoint, forKey: .authorizationEndpoint)
        try container.encodeIfPresent(tokenEndpoint, forKey: .tokenEndpoint)
        try container.encodeIfPresent(deviceAuthorizationEndpoint, forKey: .deviceAuthorizationEndpoint)
        try container.encodeIfPresent(revocationEndpoint, forKey: .revocationEndpoint)
        try container.encodeIfPresent(codeChallengeMethodsSupported, forKey: .codeChallengeMethodsSupported)
        try container.encodeIfPresent(grantTypesSupported, forKey: .grantTypesSupported)
        try container.encodeIfPresent(
            authorizationResponseIssParameterSupported, forKey: .authorizationResponseIssParameterSupported)
        for (name, value) in additionalFields where !Key.known.contains(name) {
            try container.encode(value, forKey: Key(name))
        }
    }
}
