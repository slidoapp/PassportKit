import Foundation
import PassportKit
import PassportKitTesting
import Testing

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Specification §15: a run of every flow with canary secrets must leave no canary in any error, event or
/// rendering of a public value. The canaries are the client secret and every token, code, verifier and device
/// code that crossed the wire, including the ones the fake server issued.
@Suite("Redaction canary: no secret in any description", .timeLimit(.minutes(1)))
struct RedactionCanaryTests {
    private static let clientSecret = "canary-client-secret-0123456789abcdefghij"
    private static let longRefreshToken = "canary-long-refresh-token-0123456789abcdefghijklmnop"
    private static let longAccessToken = "canary-long-access-token-0123456789abcdefghijklmnopq"

    /// A client, its server, and the logs every scenario writes to.
    private struct Rig {
        let server: FakeAuthorizationServer
        let harvest = SecretHarvest()
        let renderings = RenderingLog()
        let events = EventLog()
        let clock = ManualClock()
        let wallClock = ManualWallClock()
        let client: OAuthClient

        init(authentication: (Secret) -> ClientAuthentication) async throws {
            let registration = FakeAuthorizationServer.ClientRegistration(
                id: "app", secret: Secret(RedactionCanaryTests.clientSecret),
                allowedGrants: [.authorizationCode, .refreshToken, .clientCredentials, .tokenExchange, .deviceCode],
                scope: ["read", "write"], rotatesRefreshTokens: true)
            let server = FakeAuthorizationServer(clients: [registration], wallClock: wallClock, clock: clock)
            self.server = server
            let harvest = harvest
            await server.configure { $0.override = { harvest.override(for: $0) } }
            harvest.add(RedactionCanaryTests.clientSecret)
            client = try OAuthClient(
                configuration: ClientConfiguration(
                    endpoints: Endpoints(
                        authorization: FakeAuthorizationServer.authorizationEndpoint,
                        token: FakeAuthorizationServer.tokenEndpoint,
                        deviceAuthorization: FakeAuthorizationServer.deviceAuthorizationEndpoint,
                        revocation: FakeAuthorizationServer.revocationEndpoint),
                    authentication: authentication(Secret(RedactionCanaryTests.clientSecret)),
                    issuer: FakeAuthorizationServer.issuer),
                transport: HarvestingTransport(server: server, harvest: harvest), wallClock: wallClock,
                clock: clock, random: SequenceRandomSource(), observer: events)
        }

        func authorize() async throws -> TokenResponse {
            try await client.authorize(
                AuthorizationRequest(redirectURI: redirectURI, scope: ["read", "write"]),
                using: server.userAgent())
        }

        func echo(_ code: String, path: String = "/token", status: Int = 400, of parameters: [String]) {
            harvest.echoing(.init(path: path, status: status, code: code, parameters: parameters))
        }
    }

    private static func assertNoCanary(
        _ rig: Rig, minimumSecrets: Int = 12, minimumRenderings: Int = 100,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        let secrets = rig.harvest.all
        #expect(
            secrets.count >= minimumSecrets, "the scenarios must have produced secrets to look for",
            sourceLocation: sourceLocation)
        let events = rig.events.all.flatMap { [String(describing: $0), String(reflecting: $0)] }
        let renderings = rig.renderings.all + events
        #expect(
            renderings.count >= minimumRenderings, "the scenarios must have rendered values",
            sourceLocation: sourceLocation)
        for secret in secrets where secret.count >= 6 {
            let leaks = renderings.filter { $0.contains(secret) }
            #expect(
                leaks.isEmpty, "a secret appears in \(leaks.count) renderings: \(leaks.prefix(2))",
                sourceLocation: sourceLocation)
        }
    }

    @Test("Every OAuthClient flow, successful and failing", arguments: [0, 1])
    func clientFlows(authenticationMode: Int) async throws {
        let rig = try await Rig { secret in
            switch authenticationMode {
            case 0: .clientSecretPost(clientID: "app", secret: secret)
            default: .clientSecretBasic(clientID: "app", secret: secret)
            }
        }
        let client = rig.client
        rig.renderings.look(client)
        rig.renderings.look(client.configuration)
        rig.renderings.look(client.configuration.authentication)

        // Authorization code with PKCE, step by step and in one call.
        let pending = try client.beginAuthorization(
            AuthorizationRequest(redirectURI: redirectURI, scope: ["read"]))
        rig.renderings.look(pending)
        let grant = try #require(await rig.renderings.observe { try await rig.authorize() })
        let refreshed = try #require(
            await rig.renderings.observe { try await client.refresh(grant.refreshToken!) })
        _ = await rig.renderings.observe { try await client.clientCredentials(scope: ["read"]) }

        // Token exchange with both subject token types; the refresh token subject rotates.
        _ = await rig.renderings.observe {
            try await client.exchange(
                TokenExchangeRequest(
                    subjectToken: refreshed.accessToken, subjectTokenType: .accessToken, audiences: ["service"]))
        }
        let exchanged = try #require(
            await rig.renderings.observe {
                try await client.exchange(
                    TokenExchangeRequest(
                        subjectToken: refreshed.refreshToken!, subjectTokenType: .refreshToken,
                        requestedTokenType: .refreshToken, audiences: ["service"]))
            })
        _ = await rig.renderings.observe { try await client.revoke(exchanged.refreshToken ?? refreshed.refreshToken!) }

        // The device flow, driven with the manual clock.
        let device = try #require(
            await rig.renderings.observe { try await client.beginDeviceAuthorization(scope: ["read"]) })
        try await rig.server.approve(userCode: device.userCode)
        async let polled = client.completeDeviceAuthorization(device)
        _ = await rig.clock.advanceToNextSleeper()
        rig.renderings.look(try await polled)

        // Error paths whose server echoes the secrets it was sent. The mix of short fake tokens and the
        // client secret covers both the 24-character run rule and the request-specific redaction.
        let spent = try #require(grant.refreshToken)
        rig.echo("invalid_grant", of: ["refresh_token", "client_secret", "basic_secret"])
        _ = await rig.renderings.observe { try await client.refresh(spent) }
        rig.echo("access_denied", status: 401, of: ["subject_token", "client_secret", "basic_secret"])
        _ = await rig.renderings.observe {
            try await client.exchange(
                TokenExchangeRequest(
                    subjectToken: refreshed.accessToken, subjectTokenType: .accessToken, audiences: ["service"]))
        }
        rig.echo("invalid_client", of: ["client_secret", "basic_secret"])
        _ = await rig.renderings.observe { try await client.clientCredentials(scope: ["read"]) }
        rig.echo("unsupported_token_type", of: ["token", "client_secret", "basic_secret"])
        _ = await rig.renderings.observe { try await client.revoke(spent) }
        rig.echo("invalid_scope", path: "/device_authorization", of: ["client_secret", "basic_secret"])
        _ = await rig.renderings.observe { try await client.beginDeviceAuthorization(scope: ["read"]) }

        rig.echo("access_denied", of: ["device_code", "client_secret", "basic_secret"])
        let denied = try await client.beginDeviceAuthorization(scope: ["read"])
        async let deniedPoll = rig.renderings.observe { try await client.completeDeviceAuthorization(denied) }
        _ = await rig.clock.advanceToNextSleeper()
        _ = await deniedPoll

        rig.echo("invalid_grant", of: ["code", "code_verifier", "client_secret", "basic_secret"])
        _ = await rig.renderings.observe { try await rig.authorize() }
        rig.harvest.echoing(nil)

        // Authorization callback checks: an error response that echoes the state, and a state mismatch.
        let state = URLComponents(url: pending.url, resolvingAgainstBaseURL: false)?.queryItems?
            .first { $0.name == "state" }?.value
        rig.harvest.add(try #require(state))
        var callback = URLComponents(url: redirectURI, resolvingAgainstBaseURL: false)!
        callback.queryItems = [
            URLQueryItem(name: "error", value: "access_denied"),
            URLQueryItem(name: "error_description", value: "state \(state!) was refused"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "iss", value: FakeAuthorizationServer.issuer.absoluteString),
        ]
        _ = await rig.renderings.observe {
            try await client.completeAuthorization(pending, callbackURL: callback.url!)
        }
        _ = await rig.renderings.observe { try await client.completeAuthorization(pending, callbackURL: callback.url!) }
        let other = try client.beginAuthorization(AuthorizationRequest(redirectURI: redirectURI))
        callback.queryItems = [
            URLQueryItem(name: "code", value: "wrong-code-value"), URLQueryItem(name: "state", value: "x"),
        ]
        _ = await rig.renderings.observe { try await client.completeAuthorization(other, callbackURL: callback.url!) }

        // Transport failure.
        await rig.server.configure { $0.override = { _ in .init(failure: URLError(.notConnectedToInternet)) } }
        _ = await rig.renderings.observe { try await client.refresh(spent) }

        Self.assertNoCanary(rig)
    }

    private static func collect(_ stream: AsyncStream<SessionEvent>) -> Task<[SessionEvent], Never> {
        Task {
            var events: [SessionEvent] = []
            for await event in stream {
                events.append(event)
                if case .signedOut = event { break }
            }
            return events
        }
    }

    @Test("TokenManager, RequestAuthorizer and the credential store")
    func sessionFlows() async throws {
        let rig = try await Rig { .clientSecretPost(clientID: "app", secret: $0) }
        let store = InMemoryCredentialStore()
        let account = CredentialAccount(service: "canary", account: "user")
        let manager = TokenManager(client: rig.client, store: store, account: account)
        let events = Self.collect(manager.events)
        let authorizer = RequestAuthorizer(manager: manager, transport: rig.server)
        let resource = HTTPRequest(method: .get, url: URL(string: "https://api.example.com/items")!)

        let grant = try await rig.authorize()
        try await manager.signIn(with: grant, requestedScope: ["read", "write"])
        rig.renderings.look(manager)
        rig.renderings.look(authorizer)
        rig.renderings.look(store)
        rig.renderings.look(await manager.credential as Any)
        rig.renderings.look(try #require(await store.load(account)))
        let root = try #require(await rig.renderings.observe { try await manager.accessToken() })
        await rig.renderings.observe {
            try await manager.accessToken(for: TokenTarget.refreshGrant(resources: [apiA], scope: ["read"]))
        }
        await rig.renderings.observe {
            try await manager.accessToken(for: TokenTarget.exchange(audiences: ["service"]))
        }
        await rig.renderings.observe { try await manager.exchangeRefreshToken(audiences: ["service"]) }
        // The signed `URLRequest` of the other overload is Foundation's own type and prints its headers; the
        // token that came with it is ours.
        rig.renderings.look(try await authorizer.sign(URLRequest(url: resource.url)).1)
        let (signed, token) = try await authorizer.sign(resource)
        rig.renderings.look(signed)
        rig.renderings.look(token)
        await rig.renderings.observe { try await authorizer.send(resource) }
        await manager.invalidate(root)

        // The resource answers with a challenge that repeats the bearer token.
        rig.harvest.challenging(true)
        await rig.renderings.observe { try await authorizer.send(resource) }
        rig.harvest.challenging(false)

        // The server rejects the refresh token and echoes it; the session ends.
        rig.wallClock.advance(by: .seconds(100_000))
        rig.echo("invalid_grant", of: ["refresh_token", "client_secret"])
        await rig.renderings.observe { try await manager.accessToken() }
        rig.harvest.echoing(nil)
        await rig.renderings.observe { try await manager.accessToken() }
        for event in await events.value { rig.renderings.look(event) }

        // A second session signs out, which revokes the refresh token, then fails to revoke.
        let again = try await rig.authorize()
        try await manager.signIn(with: again, requestedScope: ["read"])
        let signedOut = Self.collect(manager.events)
        rig.echo("unsupported_token_type", of: ["token", "client_secret"])
        rig.renderings.look(await manager.signOut())
        for event in await signedOut.value { rig.renderings.look(event) }

        Self.assertNoCanary(rig)
    }

    @Test("Long tokens echoed by a server are redacted by the description rules too")
    func longTokens() async throws {
        let rig = try await Rig { .clientSecretBasic(clientID: "app", secret: $0) }
        let manager = TokenManager(
            client: rig.client, store: InMemoryCredentialStore(),
            account: CredentialAccount(service: "canary", account: "long"))
        let events = Self.collect(manager.events)
        for secret in [Self.longRefreshToken, Self.longAccessToken] { rig.harvest.add(secret) }
        try await manager.signIn(
            with: TokenResponse(
                accessToken: Secret(Self.longAccessToken), tokenType: "Bearer", expiresIn: .seconds(60),
                refreshToken: Secret(Self.longRefreshToken)), requestedScope: ["read"])
        rig.wallClock.advance(by: .seconds(1000))
        rig.echo("invalid_grant", of: ["refresh_token", "basic_secret"])
        await rig.renderings.observe { try await manager.accessToken() }
        for event in await events.value { rig.renderings.look(event) }
        Self.assertNoCanary(rig, minimumSecrets: 3, minimumRenderings: 10)
    }
}
