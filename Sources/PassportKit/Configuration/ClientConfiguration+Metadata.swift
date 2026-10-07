import Foundation

extension ClientConfiguration {
    /// Creates a configuration from discovered metadata (RFC 8414 §2, RFC 9207 §3).
    ///
    /// Takes the endpoints and the ``issuer`` from `metadata` and sets ``requiresIssuerInAuthorizationResponse``
    /// when the server advertises `authorization_response_iss_parameter_supported`, so the mix-up defence of
    /// RFC 9207 is on whenever the server supports it.
    ///
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/invalidConfiguration`` when the
    /// endpoints or the issuer fail validation (not `https`) or the metadata has no `token_endpoint`.
    public init(
        metadata: AuthorizationServerMetadata,
        authentication: ClientAuthentication,
        additionalHeaders: HTTPHeaders = [:],
        minimumTokenLifetime: Duration = .seconds(60),
        defaultTokenLifetime: Duration? = nil
    ) throws {
        self.init(
            endpoints: try Endpoints(metadata: metadata),
            authentication: authentication,
            issuer: metadata.issuer,
            additionalHeaders: additionalHeaders,
            minimumTokenLifetime: minimumTokenLifetime,
            defaultTokenLifetime: defaultTokenLifetime,
            requiresIssuerInAuthorizationResponse: metadata.authorizationResponseIssParameterSupported == true
        )
        try validate()
    }
}
