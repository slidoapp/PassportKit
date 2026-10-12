import Foundation
import HTTPTypes

/// Everything the client needs to know about itself and its authorization server.
///
/// Header values can carry credentials, so descriptions and reflection show the names of
/// ``additionalHeaders`` and never their values.
public struct ClientConfiguration: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The authorization server endpoints.
    public var endpoints: Endpoints
    /// How the client authenticates.
    public var authentication: ClientAuthentication
    /// The expected issuer, used for RFC 9207 `iss` checks.
    public var issuer: URL?
    /// Header fields sent on every request to the authorization server. Library-owned fields (`Content-Type`,
    /// `Accept`, `Authorization` for Basic client authentication) replace fields of the same name.
    public var additionalHeaders: HTTPFields
    /// Tokens are refreshed when less than this remains before expiry.
    public var minimumTokenLifetime: Duration
    /// The lifetime assumed when `expires_in` is missing; `nil` treats such tokens as expired.
    public var defaultTokenLifetime: Duration?
    /// Whether an authorization response must carry `iss` (RFC 9207 §2.4). Set it when the server's metadata
    /// advertises `authorization_response_iss_parameter_supported`. Needs ``issuer``.
    public var requiresIssuerInAuthorizationResponse: Bool

    /// Creates a configuration.
    public init(
        endpoints: Endpoints,
        authentication: ClientAuthentication,
        issuer: URL? = nil,
        additionalHeaders: HTTPFields = [:],
        minimumTokenLifetime: Duration = .seconds(60),
        defaultTokenLifetime: Duration? = nil,
        requiresIssuerInAuthorizationResponse: Bool = false
    ) {
        self.endpoints = endpoints
        self.authentication = authentication
        self.issuer = issuer
        self.additionalHeaders = additionalHeaders
        self.minimumTokenLifetime = minimumTokenLifetime
        self.defaultTokenLifetime = defaultTokenLifetime
        self.requiresIssuerInAuthorizationResponse = requiresIssuerInAuthorizationResponse
    }

    /// A summary that shows the token endpoint and the names of the additional headers, never their values.
    public var description: String {
        "ClientConfiguration(token: \(endpoints.token.redactedTarget), additionalHeaders: \(additionalHeaders.names))"
    }

    /// Same as ``description``.
    public var debugDescription: String { description }

    /// A mirror that lists the members but shows the names of ``additionalHeaders`` instead of its values.
    public var customMirror: Mirror {
        Mirror(
            self,
            children: [
                "endpoints": endpoints,
                "authentication": authentication,
                "issuer": issuer as Any,
                "additionalHeaders": additionalHeaders.names,
                "minimumTokenLifetime": minimumTokenLifetime,
                "defaultTokenLifetime": defaultTokenLifetime as Any,
                "requiresIssuerInAuthorizationResponse": requiresIssuerInAuthorizationResponse,
            ],
            displayStyle: .struct
        )
    }

    /// Checks the endpoints and issuer: `https`, or `http` with a loopback host only, and that
    /// ``requiresIssuerInAuthorizationResponse`` has an ``issuer`` to compare with.
    ///
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/invalidConfiguration`` otherwise.
    func validate() throws {
        try endpoints.validate()
        if let issuer {
            try Endpoints.validateSecureTransport(of: issuer, name: "issuer")
        }
        if requiresIssuerInAuthorizationResponse, issuer == nil {
            throw PassportError(
                .invalidConfiguration,
                detail: "Requiring an issuer in the authorization response needs a configured issuer."
            )
        }
    }
}
