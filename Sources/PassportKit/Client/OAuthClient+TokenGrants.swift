import Foundation

extension OAuthClient {
    /// Redeems a refresh token (RFC 6749 §6), optionally narrowing `scope` and binding to `resources` (RFC 8707 §2).
    ///
    /// `invalid_grant` is reported with recovery ``PassportError/Recovery-swift.enum/reauthenticate``.
    public func refresh(
        _ refreshToken: Secret,
        scope: ScopeSet? = nil,
        resources: [URL] = [],
        additionalParameters: AdditionalParameters = [:]
    ) async throws -> TokenResponse {
        var request = FormRequest(tokenEndpoint: configuration.endpoints.token, grantType: .refreshToken)
        request.add("refresh_token", refreshToken.reveal())
        request.add(scope: scope)
        try request.add(resources: resources)
        request.additionalParameters = additionalParameters
        return try await performTokenRequest(request, context: .refreshGrant)
    }

    /// Requests a token for the client itself (RFC 6749 §4.4).
    public func clientCredentials(
        scope: ScopeSet? = nil,
        resources: [URL] = [],
        additionalParameters: AdditionalParameters = [:]
    ) async throws -> TokenResponse {
        var request = FormRequest(tokenEndpoint: configuration.endpoints.token, grantType: .clientCredentials)
        request.add(scope: scope)
        try request.add(resources: resources)
        request.additionalParameters = additionalParameters
        return try await performTokenRequest(request, context: .other)
    }

    /// Exchanges one token for another (RFC 8693 §2.1), with `audience` (§2.1) and `resource` (RFC 8707 §2) targets.
    ///
    /// A response without `token_type` is accepted when `issued_token_type` is not an access token (§2.2.1).
    /// `invalid_grant` for a refresh-token subject has recovery
    /// ``PassportError/Recovery-swift.enum/reauthenticate``; a 401 `access_denied` is
    /// ``PassportError/Recovery-swift.enum/resourceDenied``.
    public func exchange(_ exchange: TokenExchangeRequest) async throws -> TokenResponse {
        if (exchange.actorToken == nil) != (exchange.actorTokenType == nil) {
            throw PassportError(
                .invalidConfiguration,
                detail: "actor_token and actor_token_type must be given together."
            )
        }
        var request = FormRequest(tokenEndpoint: configuration.endpoints.token, grantType: .tokenExchange)
        request.add("subject_token", exchange.subjectToken.reveal())
        request.add("subject_token_type", exchange.subjectTokenType.rawValue)
        if let actorToken = exchange.actorToken, let actorTokenType = exchange.actorTokenType {
            request.add("actor_token", actorToken.reveal())
            request.add("actor_token_type", actorTokenType.rawValue)
        }
        if let requestedTokenType = exchange.requestedTokenType {
            request.add("requested_token_type", requestedTokenType.rawValue)
        }
        for audience in exchange.audiences { request.add("audience", audience) }
        try request.add(resources: exchange.resources)
        request.add(scope: exchange.scope)
        request.additionalParameters = exchange.additionalParameters
        let context: ErrorResponseContext =
            exchange.subjectTokenType == .refreshToken ? .exchangeWithRefreshToken : .other
        return try await performTokenRequest(request, context: context, exchange: true)
    }

    /// Sends an extension grant (RFC 6749 §4.5) with `parameters` after `grant_type` and client authentication.
    ///
    /// Responses and errors are handled as for the standard grants; a `refresh_token` grant is classified as a
    /// refresh. Parameter names that collide with `grant_type` or the client credentials throw
    /// ``PassportError/Code-swift.struct/invalidConfiguration``.
    public func requestToken(grantType: GrantType, parameters: AdditionalParameters) async throws -> TokenResponse {
        var request = FormRequest(tokenEndpoint: configuration.endpoints.token, grantType: grantType)
        request.additionalParameters = parameters
        return try await performTokenRequest(request, context: grantType == .refreshToken ? .refreshGrant : .other)
    }
}
