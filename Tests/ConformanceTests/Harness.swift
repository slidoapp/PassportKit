import Foundation
import PassportKit
import PassportKitTesting
import Testing

/// Counts how many requests are in flight at once, to prove the refresh token lane never overlaps.
actor RequestGauge {
    private var current = 0
    private(set) var peak = 0
    /// The refresh tokens the server issued, in order, as seen on the wire.
    private(set) var issuedRefreshTokens: [String] = []

    func enter() {
        current += 1
        peak = max(peak, current)
    }

    func leave() { current -= 1 }

    func record(_ response: HTTPResponse) {
        let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any]
        if let token = object?["refresh_token"] as? String { issuedRefreshTokens.append(token) }
    }
}

struct GaugedTransport: HTTPTransport {
    let server: FakeAuthorizationServer
    let gauge: RequestGauge

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        await gauge.enter()
        do {
            let response = try await server.send(request)
            await gauge.leave()
            await gauge.record(response)
            return response
        } catch {
            await gauge.leave()
            throw error
        }
    }
}

let redirectURI = URL(string: "https://app.example.com/callback")!
let apiA = URL(string: "https://api.example.com/a")!
let apiB = URL(string: "https://api.example.com/b")!
let deniedResource = URL(string: "https://api.example.com/denied/x")!

/// A fake server, a signed-in manager and the seams around them.
///
/// Rotation is on and the server grants no reuse by default, and a reused refresh token revokes its grant, so
/// any violation of the lane, persistence or generation invariants shows as `invalid_grant`.
struct Harness {
    let server: FakeAuthorizationServer
    let clock = ManualClock()
    let wallClock = ManualWallClock()
    let gauge = RequestGauge()
    let store: any CredentialStore
    let account = CredentialAccount(service: "conformance", account: "user")
    let client: OAuthClient
    let manager: TokenManager
    /// Subscribed before signing in, so it starts with `.signedIn`.
    let events: AsyncStream<SessionEvent>

    init(
        rotates: Bool = true,
        leeway: FakeAuthorizationServer.RotationLeeway? = nil,
        policy: any TokenAcceptancePolicy = AcceptAnyToken(),
        minimumTokenLifetime: Duration = .seconds(60),
        defaultTokenLifetime: Duration? = nil,
        accessTokenLifetime: Duration = .seconds(900),
        store: any CredentialStore = InMemoryCredentialStore(),
        rejectedTokenCacheDuration: Duration = .seconds(30),
        signedIn: Bool = true
    ) async throws {
        self.store = store
        let registration = FakeAuthorizationServer.ClientRegistration(
            id: "app", allowedGrants: [.authorizationCode, .refreshToken, .tokenExchange],
            scope: ["read", "write", "admin"], rotatesRefreshTokens: rotates, rotationLeeway: leeway,
            revokesGrantOnReuse: true, accessTokenLifetime: accessTokenLifetime)
        let server = FakeAuthorizationServer(clients: [registration], wallClock: wallClock, clock: clock)
        self.server = server
        let configuration = ClientConfiguration(
            endpoints: Endpoints(
                authorization: FakeAuthorizationServer.authorizationEndpoint,
                token: FakeAuthorizationServer.tokenEndpoint,
                revocation: FakeAuthorizationServer.revocationEndpoint),
            authentication: .publicClient(clientID: "app"), issuer: FakeAuthorizationServer.issuer,
            minimumTokenLifetime: minimumTokenLifetime, defaultTokenLifetime: defaultTokenLifetime)
        client = try OAuthClient(
            configuration: configuration, transport: GaugedTransport(server: server, gauge: gauge),
            wallClock: wallClock, clock: clock, random: SequenceRandomSource())
        manager = TokenManager(
            client: client, store: store, account: account, acceptancePolicy: policy,
            rejectedTokenCacheDuration: rejectedTokenCacheDuration)
        events = manager.events
        if signedIn { try await signInAgain() }
    }

    /// Runs a full authorization code flow at the fake server and returns its tokens.
    func grant() async throws -> TokenResponse {
        try await client.authorize(
            AuthorizationRequest(redirectURI: redirectURI, scope: ["read", "write"]),
            using: server.userAgent())
    }

    /// Signs in with a new grant.
    @discardableResult
    func signInAgain() async throws -> TokenResponse {
        let response = try await grant()
        try await manager.signIn(with: response, requestedScope: ["read", "write"])
        return response
    }

    /// The refresh token in the store, or `nil`.
    func storedRefreshToken() async -> String? {
        (try? await store.load(account))?.refreshToken?.reveal()
    }

    /// The newest refresh token the server has issued, whether or not the manager saw it.
    func newestIssuedRefreshToken() async -> String? {
        await gauge.issuedRefreshTokens.last
    }

    /// The refresh token the manager holds, or `nil`.
    func currentRefreshToken() async -> String? {
        await manager.credential?.refreshToken?.reveal()
    }

    /// Makes every access token held so far unusable by the wall clock, without touching refresh tokens.
    func expireAccessTokens() {
        wallClock.advance(by: .seconds(1000))
    }

    /// Token endpoint requests of one grant type, in order.
    func tokenRequests(_ grantType: GrantType) async -> [RecordedRequest] {
        await server.requests(to: "/token").filter { $0.value("grant_type") == grantType.rawValue }
    }

    /// The refresh tokens the server was shown, in order, from refresh grants and refresh token exchanges.
    func presentedRefreshTokens() async -> [String] {
        await server.requests(to: "/token").compactMap { request in
            switch request.value("grant_type") {
            case GrantType.refreshToken.rawValue: request.value("refresh_token")
            case GrantType.tokenExchange.rawValue
            where request.value("subject_token_type") == TokenTypeIdentifier.refreshToken.rawValue:
                request.value("subject_token")
            default: nil
            }
        }
    }

    /// Delays every answer to a refresh or exchange by `duration` on the manual clock, after the server acted.
    func delayTokenResponses(by duration: Duration = .seconds(10)) async {
        await server.configure {
            $0.responseDelay = {
                $0.path == "/token" && $0.value("grant_type") != "authorization_code" ? duration : nil
            }
        }
    }

    /// Advances the manual clock to each of the next `count` sleepers, one request answer at a time.
    func deliverResponses(_ count: Int) async {
        for _ in 0..<count { await clock.advanceToNextSleeper() }
    }

    /// The next `count` events.
    static func take(_ count: Int, from stream: AsyncStream<SessionEvent>) async -> [SessionEvent] {
        var iterator = stream.makeAsyncIterator()
        var taken: [SessionEvent] = []
        while taken.count < count, let event = await iterator.next() { taken.append(event) }
        return taken
    }
}

/// The `PassportError` thrown by `operation`, or `nil` when it succeeds. Any other error fails the test.
func thrownError<Value>(_ operation: () async throws -> Value) async -> PassportError? {
    do {
        _ = try await operation()
        return nil
    } catch let error as PassportError {
        return error
    } catch {
        Issue.record("Unexpected error: \(error)")
        return nil
    }
}
