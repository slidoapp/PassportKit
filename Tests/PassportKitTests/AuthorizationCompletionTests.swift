import Foundation
import PassportKitTesting
import Testing

@testable import PassportKit

@Suite(.timeLimit(.minutes(1)))
struct AuthorizationCompletionTests {
    private typealias Fixtures = AuthorizationFixtures

    private func start(
        _ steps: [RecordingTransport.Step] = [.tokens("at")],
        authentication: ClientAuthentication = .none(clientID: "app"),
        issuer: URL? = nil,
        requiresIssuer: Bool = false,
        clock: any Clock<Duration> = ContinuousClock(),
        redirectURI: URL = Fixtures.redirectURI
    ) throws -> (OAuthClient, RecordingTransport, PendingAuthorization) {
        let transport = RecordingTransport(steps)
        let client = try ClientFixtures.client(
            transport, authentication: authentication, issuer: issuer, requiresIssuer: requiresIssuer, clock: clock,
            random: CountingRandomSource())
        return (client, transport, try client.beginAuthorization(AuthorizationRequest(redirectURI: redirectURI)))
    }

    private func code(_ extra: [(String, String)] = [], for pending: PendingAuthorization) -> URL {
        Fixtures.callback([("code", "the-code"), ("state", pending.state.reveal())] + extra, to: pending.redirectURI)
    }

    private func failure(
        _ client: OAuthClient, _ pending: PendingAuthorization, _ callback: URL
    ) async -> PassportError? {
        do { _ = try await client.completeAuthorization(pending, callbackURL: callback) } catch {
            return error as? PassportError
        }
        return nil
    }

    // MARK: Token request

    @Test func redeemsTheCodeWithTheVerifier() async throws {
        let (client, transport, pending) = try start()
        let response = try await client.completeAuthorization(
            pending, callbackURL: code(for: pending), additionalParameters: ["tenant": "x"])
        #expect(response.accessToken.reveal() == "at")
        let sent = try #require(await transport.requests.first)
        #expect(sent.request.url == ClientFixtures.tokenURL)
        #expect(
            sent.form.map { "\($0.0)=\($0.1)" } == [
                "grant_type=authorization_code", "code=the-code", "redirect_uri=https://app.example.com/callback",
                "code_verifier=\(CountingRandomSource.text(call: 2))", "client_id=app", "tenant=x",
            ])
    }

    @Test func confidentialClientsAuthenticateAtTheTokenEndpoint() async throws {
        let (client, transport, pending) = try start(
            authentication: .clientSecretBasic(clientID: "app", secret: Secret("s3")))
        _ = try await client.completeAuthorization(pending, callbackURL: code(for: pending))
        let sent = try #require(await transport.requests.first)
        #expect(sent.request.headers["Authorization"]?.hasPrefix("Basic ") == true)
        #expect(sent.value("client_id") == nil)
        #expect(sent.value("code_verifier") != nil)
    }

    @Test func tokenEndpointErrorsAreClassifiedByBody() async throws {
        let (client, _, pending) = try start([.oauthError("invalid_grant")])
        let error = await failure(client, pending, code(for: pending))
        #expect(error?.code == .invalidGrant)
        #expect(error?.recovery == PassportError.Recovery.none)
    }

    // MARK: Redirect match

    @Test(
        arguments: [
            "https://evil.example.com/callback", "https://app.example.com:8443/callback",
            "https://app.example.com/other", "https://app.example.com/callback/", "http://app.example.com/callback",
            "com.example.app:/callback", "https://app.example.com/Callback",
        ])
    func callbackToAnotherRedirectIsRejected(_ target: String) async throws {
        let (client, transport, pending) = try start()
        let callback = Fixtures.callback(
            [("code", "c"), ("state", pending.state.reveal())], to: URL(string: target)!)
        let error = await failure(client, pending, callback)
        #expect(error?.code == .invalidResponse)
        #expect(await transport.requests.isEmpty)
    }

    @Test func schemeHostAndDefaultPortAreMatchedLeniently() async throws {
        let (client, _, pending) = try start()
        let callback = Fixtures.callback(
            [("code", "c"), ("state", pending.state.reveal())], to: URL(string: "HTTPS://App.Example.com:443/callback")!
        )
        _ = try await client.completeAuthorization(pending, callbackURL: callback)
    }

    @Test func loopbackRedirectMustCarryTheActualPort() async throws {
        let redirect = URL(string: "http://127.0.0.1:51234/cb")!
        let (client, _, pending) = try start(redirectURI: redirect)
        let wrongPort = Fixtures.callback(
            [("code", "c"), ("state", pending.state.reveal())], to: URL(string: "http://127.0.0.1:9/cb")!)
        #expect(await failure(client, pending, wrongPort)?.code == .invalidResponse)
        _ = try await client.completeAuthorization(pending, callbackURL: code(for: pending))
    }

    @Test(arguments: [
        "state=x&state=y&code=c", "code=a&code=b", "code=%FF&state=x",
    ])
    func repeatedOrMalformedParametersAreRejected(_ query: String) async throws {
        let (client, _, pending) = try start()
        let callback = URL(string: "https://app.example.com/callback?\(query)")!
        #expect(await failure(client, pending, callback)?.code == .invalidResponse)
    }

    // MARK: State

    @Test(arguments: ["wrong", "", nil])
    func stateMismatchIsRejectedWithoutConsuming(_ state: String?) async throws {
        let (client, transport, pending) = try start()
        let callback = Fixtures.callback([("code", "c")] + (state.map { [("state", $0)] } ?? []))
        let error = await failure(client, pending, callback)
        #expect(error?.code == .stateMismatch)
        #expect(await transport.requests.isEmpty)
        _ = try await client.completeAuthorization(pending, callbackURL: code(for: pending))
    }

    @Test func constantTimeComparison() {
        #expect(AuthorizationCallback.constantTimeEquals("abc", "abc"))
        #expect(!AuthorizationCallback.constantTimeEquals("abc", "abd"))
        #expect(!AuthorizationCallback.constantTimeEquals("abc", "abcd"))
        #expect(AuthorizationCallback.constantTimeEquals("", ""))
    }

    // MARK: Error response

    @Test func accessDeniedIsTheUserDeclining() async throws {
        let (client, transport, pending) = try start()
        let callback = Fixtures.callback([
            ("error", "access_denied"), ("error_description", "The user said no"),
            ("error_uri", "https://as.example.com/help"), ("state", pending.state.reveal()),
        ])
        let error = try #require(await failure(client, pending, callback))
        #expect(error.code == .accessDenied)
        #expect(error.recovery == PassportError.Recovery.none)
        #expect(error.errorDescription == "The user said no")
        #expect(error.errorURI == URL(string: "https://as.example.com/help"))
        #expect(await transport.requests.isEmpty)
    }

    @Test func otherAuthorizationErrorsKeepTheirCode() async throws {
        let (client, _, pending) = try start()
        let callback = Fixtures.callback([("error", "invalid_scope"), ("state", pending.state.reveal())])
        let error = await failure(client, pending, callback)
        #expect(error?.code == .invalidScope)
        #expect(error?.recovery == .fixConfiguration)
    }

    @Test func errorResponsesNeedAValidState() async throws {
        let (client, _, pending) = try start()
        let error = await failure(
            client, pending, Fixtures.callback([("error", "access_denied"), ("state", "forged")]))
        #expect(error?.code == .stateMismatch)
    }

    // MARK: Issuer

    @Test func matchingIssuerIsAccepted() async throws {
        let (client, _, pending) = try start(issuer: Fixtures.issuer)
        _ = try await client.completeAuthorization(
            pending, callbackURL: code([("iss", "https://as.example.com")], for: pending))
    }

    @Test(arguments: ["https://evil.example.com", "https://as.example.com/", "HTTPS://as.example.com", ""])
    func differentIssuerIsRejected(_ issuer: String) async throws {
        let (client, transport, pending) = try start(issuer: Fixtures.issuer)
        let error = await failure(client, pending, code([("iss", issuer)], for: pending))
        #expect(error?.code == .issuerMismatch)
        #expect(await transport.requests.isEmpty)
    }

    @Test func issuerIsCheckedBeforeTheErrorParameter() async throws {
        let (client, _, pending) = try start(issuer: Fixtures.issuer)
        let callback = Fixtures.callback([
            ("error", "access_denied"), ("state", pending.state.reveal()), ("iss", "https://evil.example.com"),
        ])
        #expect(await failure(client, pending, callback)?.code == .issuerMismatch)
    }

    @Test func missingIssuerFailsOnlyWhenRequired() async throws {
        let (required, _, pendingRequired) = try start(issuer: Fixtures.issuer, requiresIssuer: true)
        #expect(await failure(required, pendingRequired, code(for: pendingRequired))?.code == .issuerMismatch)

        let (optional, _, pendingOptional) = try start(issuer: Fixtures.issuer)
        _ = try await optional.completeAuthorization(pendingOptional, callbackURL: code(for: pendingOptional))
    }

    @Test func issuerIsAcceptedUncheckedWhenNoneIsConfigured() async throws {
        let (client, _, pending) = try start()
        _ = try await client.completeAuthorization(
            pending, callbackURL: code([("iss", "https://anything.example.com")], for: pending))
    }

    // MARK: Code

    @Test(arguments: [[("state", "S")], [("state", "S"), ("code", "")]])
    func missingCodeIsAnInvalidResponse(_ extra: [(String, String)]) async throws {
        let (client, transport, pending) = try start()
        let parameters = extra.map { $0.0 == "state" ? ("state", pending.state.reveal()) : $0 }
        let error = await failure(client, pending, Fixtures.callback(parameters))
        #expect(error?.code == .invalidResponse)
        #expect(await transport.requests.isEmpty)
    }

    // MARK: Single use and expiry

    @Test func aPendingAuthorizationCompletesOnce() async throws {
        let (client, transport, pending) = try start([.tokens("one"), .tokens("two")])
        _ = try await client.completeAuthorization(pending, callbackURL: code(for: pending))
        let copy = pending
        let error = await failure(client, copy, code(for: copy))
        #expect(error?.code == .invalidConfiguration)
        #expect(await transport.requests.count == 1)
    }

    @Test func aFailedRedemptionStillConsumesTheAuthorization() async throws {
        let (client, _, pending) = try start([.oauthError("invalid_grant")])
        _ = await failure(client, pending, code(for: pending))
        #expect(await failure(client, pending, code(for: pending))?.code == .invalidConfiguration)
    }

    @Test func concurrentCompletionsRedeemAtMostOnce() async throws {
        let (client, transport, pending) = try start([.tokens("one"), .tokens("two")])
        let callback = code(for: pending)
        let outcomes = await withTaskGroup(of: Bool.self) { group in
            for _ in 0..<8 {
                group.addTask { (try? await client.completeAuthorization(pending, callbackURL: callback)) != nil }
            }
            var results: [Bool] = []
            for await result in group { results.append(result) }
            return results
        }
        #expect(outcomes.filter { $0 }.count == 1)
        #expect(await transport.requests.count == 1)
    }

    @Test func expiresTenMinutesAfterCreationOnTheInjectedClock() async throws {
        let clock = ManualClock()
        let (client, transport, pending) = try start(clock: clock)
        clock.advance(by: .seconds(600))
        let error = try #require(await failure(client, pending, code(for: pending)))
        #expect(error.code == .timedOut)
        #expect(error.recovery == .reauthenticate)
        #expect(await transport.requests.isEmpty)
    }

    @Test func justBeforeExpiryStillCompletes() async throws {
        let clock = ManualClock()
        let (client, _, pending) = try start(clock: clock)
        clock.advance(by: .seconds(599))
        _ = try await client.completeAuthorization(pending, callbackURL: code(for: pending))
    }

    @Test func lifetimeIsConfigurable() async throws {
        let clock = ManualClock()
        let client = try ClientFixtures.client(RecordingTransport([.tokens()]), clock: clock)
        let pending = try client.beginAuthorization(
            AuthorizationRequest(redirectURI: Fixtures.redirectURI, lifetime: .seconds(30)))
        clock.advance(by: .seconds(29))
        let early = pending
        #expect(!early.isExpired)
        clock.advance(by: .seconds(1))
        let error = try #require(await failure(client, pending, code(for: pending)))
        #expect(error.code == .timedOut)
    }

    @Test func nonPositiveLifetimeIsInvalidConfiguration() throws {
        let client = try ClientFixtures.client(RecordingTransport())
        #expect {
            try client.beginAuthorization(AuthorizationRequest(redirectURI: Fixtures.redirectURI, lifetime: .zero))
        } throws: { ($0 as? PassportError)?.code == .invalidConfiguration }
    }

    @Test func resourcesAreRepeatedOnTheTokenRequest() async throws {
        let transport = RecordingTransport([.tokens()])
        let client = try ClientFixtures.client(transport, random: CountingRandomSource())
        let pending = try client.beginAuthorization(
            AuthorizationRequest(
                redirectURI: Fixtures.redirectURI,
                resources: [URL(string: "https://api.example.com/a")!, URL(string: "https://api.example.com/b")!]))
        _ = try await client.completeAuthorization(pending, callbackURL: code(for: pending))
        let sent = try #require(await transport.requests.first)
        #expect(
            sent.form.filter { $0.0 == "resource" }.map(\.1) == [
                "https://api.example.com/a", "https://api.example.com/b",
            ]
        )
    }
}
