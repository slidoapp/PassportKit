import Foundation

/// A direct request to the token endpoint, sent with ``OAuthClient/requestToken(_:)`` (RFC 6749 §3.2).
///
/// Each factory is named after the grant type it sends. The authorization code and device code grants have flows of
/// their own, ``OAuthClient/completeAuthorization(_:callbackURL:additionalParameters:)`` and
/// ``OAuthClient/completeDeviceAuthorization(_:additionalParameters:)``, because they validate a redirect or poll.
/// An open set: grants can be added without breaking source compatibility. Descriptions show token values as
/// `<redacted>`, because ``Secret`` redacts itself.
public struct TokenRequest: Sendable, Hashable {
    enum Grant: Sendable, Hashable {
        case refreshToken(Secret, scope: ScopeSet?, resources: [URL])
        case clientCredentials(scope: ScopeSet?, resources: [URL])
        case tokenExchange(
            subject: SecurityToken, actor: SecurityToken?, requestedTokenType: TokenTypeIdentifier?,
            audiences: [String], resources: [URL], scope: ScopeSet?)
        case extensionGrant(GrantType)
    }

    let grant: Grant
    let additionalParameters: AdditionalParameters

    /// The `grant_type` the request sends.
    public var grantType: GrantType {
        switch grant {
        case .refreshToken: .refreshToken
        case .clientCredentials: .clientCredentials
        case .tokenExchange: .tokenExchange
        case .extensionGrant(let grantType): grantType
        }
    }

    /// Redeems a refresh token (RFC 6749 §6), optionally narrowing `scope` and binding to `resources` (RFC 8707 §2).
    ///
    /// `invalid_grant` is reported with recovery ``PassportError/Recovery-swift.enum/reauthenticate``.
    public static func refreshToken(
        _ refreshToken: Secret,
        scope: ScopeSet? = nil,
        resources: [URL] = [],
        additionalParameters: AdditionalParameters = [:]
    ) -> TokenRequest {
        TokenRequest(
            grant: .refreshToken(refreshToken, scope: scope, resources: resources),
            additionalParameters: additionalParameters)
    }

    /// Requests a token for the client itself (RFC 6749 §4.4).
    public static func clientCredentials(
        scope: ScopeSet? = nil,
        resources: [URL] = [],
        additionalParameters: AdditionalParameters = [:]
    ) -> TokenRequest {
        TokenRequest(
            grant: .clientCredentials(scope: scope, resources: resources), additionalParameters: additionalParameters)
    }

    /// Exchanges one security token for another (RFC 8693 §2.1), with `audience` (§2.1) and `resource` (RFC 8707 §2)
    /// targets.
    ///
    /// The issued token is in ``TokenResponse/accessToken`` whatever its type, and
    /// ``TokenResponse/issuedTokenType`` names the type. A response without `issued_token_type` is
    /// ``PassportError/Code-swift.struct/invalidResponse``. A response without `token_type` is accepted when
    /// `issued_token_type` is not an access token (§2.2.1).
    /// `invalid_grant` for a refresh-token subject has recovery ``PassportError/Recovery-swift.enum/reauthenticate``;
    /// a 401 `access_denied` is ``PassportError/Recovery-swift.enum/resourceDenied``.
    ///
    /// - Parameters:
    ///   - subject: The token to exchange: `subject_token` and `subject_token_type`.
    ///   - actor: A token representing the acting party: `actor_token` and `actor_token_type`.
    ///   - requestedTokenType: The type of token wanted: `requested_token_type`.
    ///   - audiences: Logical names of the target services, sent as repeated `audience` parameters.
    ///   - resources: Resource indicators, sent as repeated `resource` parameters (RFC 8707 §2).
    ///   - scope: The scope wanted.
    ///   - additionalParameters: Extra parameters appended after the standard ones.
    public static func tokenExchange(
        subject: SecurityToken,
        actor: SecurityToken? = nil,
        requestedTokenType: TokenTypeIdentifier? = nil,
        audiences: [String] = [],
        resources: [URL] = [],
        scope: ScopeSet? = nil,
        additionalParameters: AdditionalParameters = [:]
    ) -> TokenRequest {
        TokenRequest(
            grant: .tokenExchange(
                subject: subject, actor: actor, requestedTokenType: requestedTokenType, audiences: audiences,
                resources: resources, scope: scope),
            additionalParameters: additionalParameters)
    }

    /// An extension grant (RFC 6749 §4.5): `grant_type` is `grantType`, followed by client authentication and
    /// `parameters`.
    ///
    /// Responses and errors are handled as for the standard grants; a `refresh_token` grant is classified as a
    /// refresh.
    public static func extensionGrant(_ grantType: GrantType, parameters: AdditionalParameters) -> TokenRequest {
        TokenRequest(grant: .extensionGrant(grantType), additionalParameters: parameters)
    }
}

extension TokenRequest {
    /// A security token and its type identifier (RFC 8693 §2.1, §3): the subject or the actor of a token exchange.
    ///
    /// The token and its type are one value, so a request cannot send `actor_token` without `actor_token_type`.
    public struct SecurityToken: Sendable, Hashable {
        /// The token value.
        public var value: Secret
        /// The type identifier sent next to the token (RFC 8693 §3).
        public var type: TokenTypeIdentifier

        /// Creates a security token of `type`.
        public init(_ value: Secret, type: TokenTypeIdentifier) {
            self.value = value
            self.type = type
        }

        /// An access token (`urn:ietf:params:oauth:token-type:access_token`).
        public static func accessToken(_ value: Secret) -> SecurityToken { SecurityToken(value, type: .accessToken) }

        /// A refresh token (`urn:ietf:params:oauth:token-type:refresh_token`).
        public static func refreshToken(_ value: Secret) -> SecurityToken { SecurityToken(value, type: .refreshToken) }

        /// An ID token (`urn:ietf:params:oauth:token-type:id_token`).
        public static func idToken(_ value: Secret) -> SecurityToken { SecurityToken(value, type: .idToken) }

        /// A JWT (`urn:ietf:params:oauth:token-type:jwt`).
        public static func jwt(_ value: Secret) -> SecurityToken { SecurityToken(value, type: .jwt) }
    }
}
