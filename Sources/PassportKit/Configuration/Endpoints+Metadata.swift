extension Endpoints {
    /// Takes the endpoints from discovered metadata (RFC 8414 §2).
    ///
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/invalidConfiguration`` when the
    /// metadata has no `token_endpoint`, or an endpoint fails ``validate()`` (not `https`).
    public init(metadata: AuthorizationServerMetadata) throws {
        guard let token = metadata.tokenEndpoint else {
            throw PassportError(.invalidConfiguration, errorDescription: "The metadata has no token endpoint.")
        }
        self.init(
            authorization: metadata.authorizationEndpoint,
            token: token,
            deviceAuthorization: metadata.deviceAuthorizationEndpoint,
            revocation: metadata.revocationEndpoint
        )
        try validate()
    }
}
