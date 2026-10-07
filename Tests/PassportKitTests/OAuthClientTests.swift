import Foundation
import PassportKitTesting
import Testing

@testable import PassportKit

@Suite(.timeLimit(.minutes(1)))
struct OAuthClientTests {
    private func pairs(_ request: RecordedRequest) -> [String] { request.form.map { "\($0.0)=\($0.1)" } }

    @Test func initRejectsInsecureConfiguration() {
        let configuration = ClientConfiguration(
            endpoints: Endpoints(token: URL(string: "http://as.example.com/token")!),
            authentication: .none(clientID: "app")
        )
        #expect(throws: PassportError.self) { try OAuthClient(configuration: configuration) }
    }

    // MARK: Request shapes

    @Test func refreshRequestShape() async throws {
        let transport = RecordingTransport([.tokens()])
        let client = try ClientFixtures.client(
            transport,
            additionalHeaders: ["X-Trace": "t1"]
        )
        _ = try await client.refresh(
            refreshToken: Secret("rt-1"),
            scope: ["b", "a"],
            resources: [URL(string: "https://api.example.com/v1")!, URL(string: "https://other.example.com")!],
            additionalParameters: ["tenant": "x", "tenant2": "y"]
        )
        let sent = try #require(await transport.requests.first)
        #expect(sent.request.method == .post)
        #expect(sent.request.url == ClientFixtures.tokenURL)
        #expect(sent.request.headers["Content-Type"] == "application/x-www-form-urlencoded")
        #expect(sent.request.headers["Accept"] == "application/json")
        #expect(sent.request.headers["X-Trace"] == "t1")
        #expect(
            pairs(sent) == [
                "grant_type=refresh_token", "refresh_token=rt-1", "scope=a b",
                "resource=https://api.example.com/v1", "resource=https://other.example.com",
                "client_id=app", "tenant=x", "tenant2=y",
            ])
    }

    @Test func clientCredentialsWithBasicAuthentication() async throws {
        let transport = RecordingTransport([.tokens()])
        let client = try ClientFixtures.client(
            transport, authentication: .clientSecretBasic(clientID: "app", secret: Secret("s3cret")))
        _ = try await client.clientCredentials(scope: ["read"])
        let sent = try #require(await transport.requests.first)
        #expect(pairs(sent) == ["grant_type=client_credentials", "scope=read"])
        #expect(sent.request.headers["Authorization"]?.hasPrefix("Basic ") == true)
        #expect(!(String(data: sent.request.body ?? Data(), encoding: .utf8) ?? "").contains("s3cret"))
    }

    @Test func secretPostPutsCredentialsInBody() async throws {
        let transport = RecordingTransport([.tokens()])
        let client = try ClientFixtures.client(
            transport, authentication: .clientSecretPost(clientID: "app", secret: Secret("s3cret")))
        _ = try await client.clientCredentials()
        let sent = try #require(await transport.requests.first)
        #expect(pairs(sent) == ["grant_type=client_credentials", "client_id=app", "client_secret=s3cret"])
        #expect(sent.request.headers["Authorization"] == nil)
    }

    @Test func exchangeRequestShape() async throws {
        let transport = RecordingTransport([.tokens()])
        let client = try ClientFixtures.client(transport)
        _ = try await client.exchange(
            TokenExchangeRequest(
                subjectToken: Secret("subject"),
                subjectTokenType: .refreshToken,
                actorToken: Secret("actor"),
                actorTokenType: .jwt,
                requestedTokenType: .accessToken,
                audiences: ["svc-a", "svc-b"],
                resources: [URL(string: "https://api.example.com")!],
                scope: ["x"],
                additionalParameters: ["extra": "1"]
            ))
        let sent = try #require(await transport.requests.first)
        #expect(
            pairs(sent) == [
                "grant_type=urn:ietf:params:oauth:grant-type:token-exchange",
                "subject_token=subject",
                "subject_token_type=urn:ietf:params:oauth:token-type:refresh_token",
                "actor_token=actor", "actor_token_type=urn:ietf:params:oauth:token-type:jwt",
                "requested_token_type=urn:ietf:params:oauth:token-type:access_token",
                "audience=svc-a", "audience=svc-b", "resource=https://api.example.com", "scope=x",
                "client_id=app", "extra=1",
            ])
    }

    @Test func actorTokenNeedsType() async throws {
        let client = try ClientFixtures.client(RecordingTransport())
        await #expect(throws: PassportError.self) {
            try await client.exchange(
                TokenExchangeRequest(
                    subjectToken: Secret("s"), subjectTokenType: .accessToken, actorToken: Secret("a")))
        }
    }

    @Test func extensionGrantRequestShape() async throws {
        let transport = RecordingTransport([.tokens()])
        let client = try ClientFixtures.client(transport)
        _ = try await client.requestToken(
            grantType: GrantType(rawValue: "urn:example:custom"), parameters: ["assertion": "a b", "assertion2": "c"])
        let sent = try #require(await transport.requests.first)
        #expect(pairs(sent) == ["grant_type=urn:example:custom", "client_id=app", "assertion=a b", "assertion2=c"])
    }

    @Test(arguments: ["grant_type", "client_id", "refresh_token", "scope", "resource"])
    func additionalParameterCollisionIsRejectedBeforeSending(name: String) async throws {
        let transport = RecordingTransport([.tokens()])
        let client = try ClientFixtures.client(transport)
        var parameters = AdditionalParameters()
        parameters.append(name, "evil")
        await #expect(throws: PassportError.self) {
            try await client.refresh(
                refreshToken: Secret("rt"), scope: ["a"], resources: [URL(string: "https://api.example.com")!],
                additionalParameters: parameters)
        }
        #expect(await transport.requests.isEmpty)
    }

    @Test(arguments: ["/relative", "https://api.example.com/x#frag", "https://api.example.com/x#", "no-scheme"])
    func invalidResourcesAreRejected(text: String) async throws {
        let transport = RecordingTransport([.tokens()])
        let client = try ClientFixtures.client(transport)
        let error = await #expect(throws: PassportError.self) {
            try await client.clientCredentials(resources: [URL(string: text)!])
        }
        #expect(error?.code == .invalidConfiguration)
        #expect(await transport.requests.isEmpty)
    }

    // MARK: Responses

    @Test func parsesTokenResponse() async throws {
        let transport = RecordingTransport([.tokens("new", extra: #","refresh_token":"rt2","scope":"a""#)])
        let client = try ClientFixtures.client(transport)
        let response = try await client.refresh(refreshToken: Secret("rt"))
        #expect(response.accessToken.reveal() == "new")
        #expect(response.refreshToken?.reveal() == "rt2")
        #expect(response.scope == ["a"])
    }

    @Test func exchangeToleratesMissingTokenTypeForNonAccessTokens() async throws {
        let body = #"{"access_token":"x","issued_token_type":"urn:ietf:params:oauth:token-type:jwt"}"#
        let transport = RecordingTransport([.json(200, body), .json(200, #"{"access_token":"x"}"#)])
        let client = try ClientFixtures.client(transport)
        let request = TokenExchangeRequest(subjectToken: Secret("s"), subjectTokenType: .accessToken)
        let response = try await client.exchange(request)
        #expect(response.tokenType == "N_A")
        let error = await #expect(throws: PassportError.self) { try await client.exchange(request) }
        #expect(error?.code == .invalidResponse)
    }

    @Test func malformedSuccessBodyIsInvalidResponse() async throws {
        let client = try ClientFixtures.client(RecordingTransport([.json(200, "not json")]))
        let error = await #expect(throws: PassportError.self) { try await client.clientCredentials() }
        #expect(error?.code == .invalidResponse)
    }

    // MARK: Error mapping

    @Test func refreshInvalidGrantMeansReauthenticate() async throws {
        let client = try ClientFixtures.client(RecordingTransport([.oauthError("invalid_grant")]))
        let error = await #expect(throws: PassportError.self) { try await client.refresh(refreshToken: Secret("rt")) }
        #expect(error?.code == .invalidGrant)
        #expect(error?.recovery == .reauthenticate)
    }

    @Test func exchangeWithRefreshTokenSubjectInvalidGrantMeansReauthenticate() async throws {
        let client = try ClientFixtures.client(RecordingTransport([.oauthError("invalid_grant")]))
        let error = await #expect(throws: PassportError.self) {
            try await client.exchange(TokenExchangeRequest(subjectToken: Secret("rt"), subjectTokenType: .refreshToken))
        }
        #expect(error?.recovery == .reauthenticate)
    }

    @Test func exchangeWithAccessTokenSubjectInvalidGrantIsNotSessionEnding() async throws {
        let client = try ClientFixtures.client(RecordingTransport([.oauthError("invalid_grant")]))
        let error = await #expect(throws: PassportError.self) {
            try await client.exchange(TokenExchangeRequest(subjectToken: Secret("at"), subjectTokenType: .accessToken))
        }
        #expect(error?.recovery == PassportError.Recovery.none)
    }

    @Test func exchange401AccessDeniedIsResourceDenied() async throws {
        let client = try ClientFixtures.client(RecordingTransport([.oauthError("access_denied", status: 401)]))
        let error = await #expect(throws: PassportError.self) {
            try await client.exchange(TokenExchangeRequest(subjectToken: Secret("rt"), subjectTokenType: .refreshToken))
        }
        #expect(error?.code == .accessDenied)
        #expect(error?.recovery == .resourceDenied)
        #expect(error?.statusCode == 401)
    }

    @Test func serviceUnavailableHonoursRetryAfter() async throws {
        let transport = RecordingTransport([.json(503, "<html>", headers: ["Retry-After": "7"])])
        let client = try ClientFixtures.client(transport)
        let error = await #expect(throws: PassportError.self) { try await client.clientCredentials() }
        #expect(error?.code == .temporarilyUnavailable)
        #expect(error?.recovery == .retryLater(after: .seconds(7)))
    }

    @Test func transportErrorIsTransportFailure() async throws {
        let client = try ClientFixtures.client(RecordingTransport([.fail(URLError(.notConnectedToInternet))]))
        let error = await #expect(throws: PassportError.self) { try await client.clientCredentials() }
        #expect(error?.code == .transportFailure)
        #expect(error?.recovery == .retryLater(after: nil))
        #expect(error?.underlying is URLError)
    }

    @Test func cancellationErrorPropagatesUnchanged() async throws {
        let client = try ClientFixtures.client(RecordingTransport([.fail(CancellationError())]))
        await #expect(throws: CancellationError.self) { try await client.clientCredentials() }
    }

    // MARK: Revocation

    @Test func revokeRequestShape() async throws {
        let transport = RecordingTransport([.json(200, "")])
        let client = try ClientFixtures.client(transport)
        try await client.revoke(Secret("rt"), typeHint: .refreshToken)
        let sent = try #require(await transport.requests.first)
        #expect(sent.request.url == ClientFixtures.revocationURL)
        #expect(pairs(sent) == ["token=rt", "token_type_hint=refresh_token", "client_id=app"])
        #expect(sent.request.headers["Accept"] == "application/json")
    }

    @Test func revokeOmitsMissingHint() async throws {
        let transport = RecordingTransport([.json(200, "")])
        try await ClientFixtures.client(transport).revoke(Secret("rt"))
        #expect(try #require(await transport.requests.first).value("token_type_hint") == nil)
    }

    @Test func revokeSucceedsOn200WhateverTheBody() async throws {
        let client = try ClientFixtures.client(
            RecordingTransport([.json(200, "garbage"), .json(200, #"{"error":"x"}"#)]))
        try await client.revoke(Secret("a"))
        try await client.revoke(Secret("b"))
    }

    @Test func revoke503IsRetryLater() async throws {
        let client = try ClientFixtures.client(RecordingTransport([.json(503, "", headers: ["Retry-After": "3"])]))
        let error = await #expect(throws: PassportError.self) { try await client.revoke(Secret("a")) }
        #expect(error?.recovery == .retryLater(after: .seconds(3)))
    }

    @Test func revokeParsesErrorJSON() async throws {
        let client = try ClientFixtures.client(RecordingTransport([.oauthError("invalid_client", status: 401)]))
        let error = await #expect(throws: PassportError.self) { try await client.revoke(Secret("a")) }
        #expect(error?.code == .invalidClient)
        #expect(error?.recovery == .fixConfiguration)
    }

    @Test func revokeWithoutEndpointIsInvalidConfiguration() async throws {
        let transport = RecordingTransport()
        let client = try ClientFixtures.client(transport, revocation: false)
        let error = await #expect(throws: PassportError.self) { try await client.revoke(Secret("a")) }
        #expect(error?.code == .invalidConfiguration)
        #expect(await transport.requests.isEmpty)
    }
}
