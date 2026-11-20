import Foundation

extension OAuthClient {
    /// Sends a direct token request (RFC 6749 §3.2) and parses the result: a refresh, client credentials, a token
    /// exchange or an extension grant.
    ///
    /// The form is `grant_type`, the parameters of the grant, client authentication, then the request's additional
    /// parameters. Additional parameters whose names collide with any of those throw
    /// ``PassportError/Code-swift.struct/invalidConfiguration``. Errors are classified by the `error` member of
    /// the response body (RFC 6749 §5.2); the factories of ``TokenRequest`` describe their recovery.
    public func requestToken(_ tokenRequest: TokenRequest) async throws -> TokenResponse {
        var request = FormRequest(tokenEndpoint: configuration.endpoints.token, grantType: tokenRequest.grantType)
        let context: ErrorResponseContext
        var isExchange = false
        switch tokenRequest.grant {
        case .refreshToken(let refreshToken, let scope, let resources):
            request.add(OAuthParameter.refreshToken, refreshToken.reveal())
            request.add(scope: scope)
            try request.add(resources: resources)
            context = .refreshGrant
        case .clientCredentials(let scope, let resources):
            request.add(scope: scope)
            try request.add(resources: resources)
            context = .other
        case .tokenExchange(let subject, let actor, let requestedTokenType, let audiences, let resources, let scope):
            request.add(OAuthParameter.subjectToken, subject.value.reveal())
            request.add(OAuthParameter.subjectTokenType, subject.type.rawValue)
            if let actor {
                request.add(OAuthParameter.actorToken, actor.value.reveal())
                request.add(OAuthParameter.actorTokenType, actor.type.rawValue)
            }
            if let requestedTokenType {
                request.add(OAuthParameter.requestedTokenType, requestedTokenType.rawValue)
            }
            for audience in audiences { request.add(OAuthParameter.audience, audience) }
            try request.add(resources: resources)
            request.add(scope: scope)
            context = subject.type == .refreshToken ? .exchangeWithRefreshToken : .other
            isExchange = true
        case .extensionGrant(let grantType):
            context = grantType == .refreshToken ? .refreshGrant : .other
        }
        request.additionalParameters = tokenRequest.additionalParameters
        return try await performTokenRequest(request, context: context, exchange: isExchange)
    }
}
