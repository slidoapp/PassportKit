import Foundation

extension OAuthClient {
    /// Starts the authorization code flow with PKCE (RFC 6749 §4.1.1, RFC 7636 §4).
    ///
    /// `state` and the PKCE verifier are 32 random bytes each, base64url (RFC 7636 §4.1, RFC 6749 §10.12); the
    /// challenge method is always `S256`. The URL is the authorization endpoint, keeping its existing query
    /// items, plus `response_type`, `client_id`, `redirect_uri`, `state`, `code_challenge`,
    /// `code_challenge_method`, `scope`, repeated `resource` (RFC 8707 §2), `login_hint`, `prompt` and the
    /// additional parameters, in that order.
    ///
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/invalidConfiguration`` when no
    /// authorization endpoint is configured, the endpoint carries a fragment or a query item the request also
    /// sets, the redirect URI is not absolute, has a fragment, or is plain `http` on a non-loopback host
    /// (RFC 8252 §7.3, §8.3), a resource is invalid, the lifetime is not positive, or an additional parameter collides.
    public func beginAuthorization(_ request: AuthorizationRequest) throws -> PendingAuthorization {
        let endpoint = try requireEndpoint(configuration.endpoints.authorization, name: "authorization")
        try Self.validate(redirectURI: request.redirectURI)
        guard request.lifetime > .zero else {
            throw PassportError(.invalidConfiguration, detail: "The authorization lifetime must be positive.")
        }
        guard var components = URLComponents(url: endpoint, resolvingAgainstBaseURL: false), components.fragment == nil
        else {
            throw PassportError(
                .invalidConfiguration,
                detail: "The authorization endpoint must not contain a fragment."
            )
        }
        let state = try PKCE.makeRandomValue(random: random)
        let verifier = try PKCE.makeVerifier(random: random)

        var builder = ParameterList()
        builder.add("response_type", "code")
        builder.add("client_id", configuration.authentication.clientID)
        builder.add("redirect_uri", request.redirectURI.absoluteString)
        builder.add("state", state.reveal())
        builder.add("code_challenge", PKCE.challenge(for: verifier))
        builder.add("code_challenge_method", PKCE.challengeMethod)
        builder.add(scope: request.scope)
        try builder.add(resources: request.resources)
        if let loginHint = request.loginHint { builder.add("login_hint", loginHint) }
        if !request.prompt.isEmpty { builder.add("prompt", request.prompt.map(\.rawValue).joined(separator: " ")) }
        let parameters = try request.additionalParameters.appending(
            to: builder.items, reserving: ClientAuthentication.parameterNames)

        let existing = components.percentEncodedQueryItems ?? []
        let names = Set(parameters.map(\.0))
        guard !existing.contains(where: { names.contains($0.name.removingPercentEncoding ?? $0.name) }) else {
            throw PassportError(
                .invalidConfiguration,
                detail: "The authorization endpoint query collides with a request parameter."
            )
        }
        let added = String(decoding: FormEncoding.encode(parameters), as: UTF8.self)
        let kept = components.percentEncodedQuery.flatMap { $0.isEmpty ? nil : $0 }
        components.percentEncodedQuery = [kept, added].compactMap { $0 }.joined(separator: "&")
        guard let url = components.url else {
            throw PassportError(.invalidConfiguration, detail: "The authorization URL could not be built.")
        }
        return PendingAuthorization(
            url: url,
            redirectURI: request.redirectURI,
            state: state,
            codeVerifier: verifier,
            resources: request.resources,
            lifetime: request.lifetime,
            stopwatch: Stopwatch(clock: clock)
        )
    }

    /// Validates the redirect and redeems the authorization code (RFC 6749 §4.1.2, §4.1.3, RFC 9207 §2.4).
    ///
    /// Checks, in order, each failing with ``PassportError``:
    /// 1. `pending` was not completed before (`invalidConfiguration`) and has not expired (`timedOut`,
    ///    recovery `reauthenticate`).
    /// 2. `callbackURL` matches the redirect URI in scheme, host, port and path, and no response parameter
    ///    repeats (`invalidResponse`). The response is read from the query only.
    /// 3. `state` equals the request's, compared in constant time (`stateMismatch`). From here on the
    ///    pending authorization is consumed.
    /// 4. `iss` equals ``ClientConfiguration/issuer`` by exact string comparison (`issuerMismatch`). It is
    ///    checked before `error` because RFC 9207 §2.4 requires it for error responses too. A missing `iss`
    ///    fails only when ``ClientConfiguration/requiresIssuerInAuthorizationResponse`` is set. When no issuer is
    ///    configured, a response `iss` is accepted unchecked.
    /// 5. An `error` response becomes the matching error (RFC 6749 §4.1.2.1); `access_denied` has recovery `none`.
    /// 6. `code` is present (`invalidResponse`).
    ///
    /// Then the code is redeemed with `grant_type`, `code`, `redirect_uri`, `code_verifier`, the request's
    /// `resource` indicators (RFC 8707 §2.2) and client authentication.
    public func completeAuthorization(
        _ pending: PendingAuthorization,
        callbackURL: URL,
        additionalParameters: AdditionalParameters = [:]
    ) async throws -> TokenResponse {
        let code = try validate(callbackURL, for: pending)
        var request = FormRequest(tokenEndpoint: configuration.endpoints.token, grantType: .authorizationCode)
        request.add("code", code.reveal())
        request.add("redirect_uri", pending.redirectURI.absoluteString)
        request.add("code_verifier", pending.codeVerifier.reveal())
        try request.add(resources: pending.resources)
        request.additionalParameters = additionalParameters
        return try await performTokenRequest(request, context: .other)
    }

    /// Runs the whole flow: begins, lets `userAgent` present the URL, and completes with its callback.
    ///
    /// Errors from `userAgent`, such as ``PassportError/Code-swift.struct/userCancelled``, propagate unchanged.
    public func authorize(_ request: AuthorizationRequest, using userAgent: any AuthorizationUserAgent) async throws
        -> TokenResponse
    {
        let pending = try beginAuthorization(request)
        let callbackURL = try await userAgent.present(pending.url, redirectURI: pending.redirectURI)
        return try await completeAuthorization(pending, callbackURL: callbackURL)
    }

    private func validate(_ callbackURL: URL, for pending: PendingAuthorization) throws -> Secret {
        guard !pending.isConsumed else {
            throw PassportError(
                .invalidConfiguration,
                detail: "This authorization was already completed; start a new one."
            )
        }
        guard !pending.isExpired else {
            throw PassportError(
                .timedOut,
                recovery: .reauthenticate,
                detail: "The authorization was not completed in time."
            )
        }
        guard AuthorizationCallback.matches(callbackURL, redirectURI: pending.redirectURI) else {
            throw PassportError(.invalidResponse, detail: "The callback does not match the redirect URI.")
        }
        guard let values = AuthorizationCallback.parameters(of: callbackURL) else {
            throw PassportError(.invalidResponse, detail: "The callback parameters are malformed.")
        }
        guard let state = values["state"], AuthorizationCallback.constantTimeEquals(state, pending.state.reveal())
        else {
            throw PassportError(.stateMismatch, detail: "The authorization response state did not match.")
        }
        guard pending.consume() else {
            throw PassportError(
                .invalidConfiguration,
                detail: "This authorization was already completed; start a new one."
            )
        }
        try validateIssuer(values["iss"])
        if let error = values["error"], !error.isEmpty {
            guard let code = PassportError.Code.fromServer(error) else {
                throw PassportError(.invalidResponse, detail: "The authorization error code is malformed.")
            }
            throw PassportError.fromServerError(
                code: code,
                detail: values["error_description"],
                errorURI: values["error_uri"].flatMap(PassportError.errorURI(from:)),
                context: .authorizationResponse
            ).redacting([pending.state.reveal(), pending.codeVerifier.reveal(), values["code"] ?? ""])
        }
        guard let code = values["code"], !code.isEmpty else {
            throw PassportError(.invalidResponse, detail: "The authorization response has no code.")
        }
        return Secret(code)
    }

    private func validateIssuer(_ issuer: String?) throws {
        guard let issuer else {
            guard !configuration.requiresIssuerInAuthorizationResponse else {
                throw PassportError(
                    .issuerMismatch,
                    detail: "The authorization response lacks the required issuer."
                )
            }
            return
        }
        if let expected = configuration.issuer, issuer != expected.absoluteString {
            throw PassportError(
                .issuerMismatch,
                detail: "The authorization response came from a different issuer."
            )
        }
    }

    private static func validate(redirectURI: URL) throws {
        let components = URLComponents(url: redirectURI, resolvingAgainstBaseURL: false)
        let scheme = components?.scheme?.lowercased()
        guard let scheme, components?.fragment == nil, scheme != "http" || LoopbackHost.isLoopback(components?.host),
            scheme != "https" || components?.host?.isEmpty == false
        else {
            throw PassportError(
                .invalidConfiguration,
                detail:
                    "The redirect URI must be absolute, without fragment, and use https, a private-use scheme, or http on a loopback host."
            )
        }
    }
}
