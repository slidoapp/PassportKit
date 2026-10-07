import Foundation

/// Everything the client needs to know about itself and its authorization server.
public struct ClientConfiguration: Sendable {
    /// The authorization server endpoints.
    public var endpoints: Endpoints
    /// How the client authenticates.
    public var authentication: ClientAuthentication
    /// The expected issuer, used for RFC 9207 `iss` checks.
    public var issuer: URL?
    /// Headers sent on every request to the authorization server.
    public var additionalHeaders: HTTPHeaders
    /// Tokens are refreshed when less than this remains before expiry.
    public var minimumTokenLifetime: Duration
    /// The lifetime assumed when `expires_in` is missing; `nil` treats such tokens as expired.
    public var defaultTokenLifetime: Duration?

    /// Creates a configuration.
    public init(
        endpoints: Endpoints,
        authentication: ClientAuthentication,
        issuer: URL? = nil,
        additionalHeaders: HTTPHeaders = [:],
        minimumTokenLifetime: Duration = .seconds(60),
        defaultTokenLifetime: Duration? = nil
    ) {
        self.endpoints = endpoints
        self.authentication = authentication
        self.issuer = issuer
        self.additionalHeaders = additionalHeaders
        self.minimumTokenLifetime = minimumTokenLifetime
        self.defaultTokenLifetime = defaultTokenLifetime
    }

    /// Checks the endpoints and issuer: `https`, or `http` with a loopback host only.
    ///
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/invalidConfiguration`` otherwise.
    public func validate() throws {
        try endpoints.validate()
        if let issuer {
            try Endpoints.validateSecureTransport(of: issuer, name: "issuer")
        }
    }
}
