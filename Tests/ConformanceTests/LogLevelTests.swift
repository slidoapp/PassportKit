import Foundation
import HTTPTypes
import Logging
import PassportKit
import PassportKitTesting
import Testing

/// Specification §12 (Logging): expected failures, such as no connectivity or a user without access to a
/// resource, are logged at `.notice`; the same lines stay at `.warning` for failures that need attention.
@Suite("Log levels of expected and unexpected failures", .timeLimit(.minutes(1)))
struct LogLevelTests {
    /// Sends to the server unless a failure is set for the path prefix, or the path is held back.
    private struct ScriptedTransport: HTTPTransport {
        let server: FakeAuthorizationServer
        let failures = Locked<[String: any Error & Sendable]>([:])
        let holding = Locked<[String: Gate]>([:])

        func send(_ request: HTTPRequest, body: Data?) async throws -> (HTTPResponse, Data) {
            let path = request.path ?? ""
            if let failure = failures.read().first(where: { path.hasPrefix($0.key) })?.value { throw failure }
            if let gate = holding.read().first(where: { path.hasPrefix($0.key) })?.value { await gate.wait() }
            return try await server.send(request, body: body)
        }
    }

    private struct Rig {
        let logs = LogCapture()
        let clock = ManualClock()
        let wallClock = ManualWallClock()
        let server: FakeAuthorizationServer
        let transport: ScriptedTransport
        let client: OAuthClient
        let manager: TokenManager

        init() async throws {
            let registration = FakeAuthorizationServer.ClientRegistration(
                id: "app", allowedGrants: [.authorizationCode, .refreshToken], scope: ["read"],
                rotatesRefreshTokens: true)
            server = FakeAuthorizationServer(clients: [registration], wallClock: wallClock, clock: clock)
            transport = ScriptedTransport(server: server)
            client = try OAuthClient(
                configuration: ClientConfiguration(
                    endpoints: Endpoints(
                        authorization: FakeAuthorizationServer.authorizationEndpoint,
                        token: FakeAuthorizationServer.tokenEndpoint,
                        revocation: FakeAuthorizationServer.revocationEndpoint),
                    authentication: .publicClient(clientID: "app"), issuer: FakeAuthorizationServer.issuer),
                transport: transport, wallClock: wallClock, clock: clock, random: SequenceRandomSource(),
                logger: logs.logger)
            manager = TokenManager(
                client: client, store: InMemoryCredentialStore(),
                account: CredentialAccount(service: "levels", account: "user"))
            let grant = try await client.authorize(
                AuthorizationRequest(redirectURI: redirectURI, scope: ["read"]), using: server.userAgent())
            try await manager.signIn(with: grant, requestedScope: ["read"])
        }

        func fail(_ path: String, with error: any Error & Sendable) { transport.failures.update { $0[path] = error } }

        func levels(of message: String) -> [Logger.Level] {
            logs.lines.filter { $0.message == message }.map(\.level)
        }
    }

    private static let offline: [URLError.Code] = [
        .notConnectedToInternet, .networkConnectionLost, .timedOut, .cannotFindHost, .cannotConnectToHost,
        .dnsLookupFailed, .dataNotAllowed, .internationalRoamingOff, .callIsActive,
    ]
    private static let notConnectivity: [any Error & Sendable] = [
        URLError(.serverCertificateUntrusted), URLError(.secureConnectionFailed), URLError(.clientCertificateRejected),
        URLError(.httpTooManyRedirects),
        PassportError(.invalidResponse, detail: "Response body exceeds the size limit."),
        // A transport failure wrapped by the URL session transport keeps the classification of its cause.
        PassportError(.transportFailure, underlying: URLError(.serverCertificateHasBadDate)),
    ]
    private static let requestFailed = "Request to the authorization server failed"
    private static let revocationFailed = "Revoking the refresh token failed"

    @Test("A token request fails: offline is a notice, any other failure a warning")
    func tokenRequest() async throws {
        let rig = try await Rig()
        for code in Self.offline {
            rig.fail("/token", with: URLError(code))
            rig.wallClock.advance(by: .seconds(100_000))
            _ = await thrownError { try await rig.manager.accessToken() }
        }
        // Also when the transport wraps the cause.
        rig.fail("/token", with: PassportError(.transportFailure, underlying: URLError(.notConnectedToInternet)))
        _ = await thrownError { try await rig.manager.accessToken() }
        #expect(rig.levels(of: Self.requestFailed) == Array(repeating: .notice, count: Self.offline.count + 1))

        for error in Self.notConnectivity {
            rig.fail("/token", with: error)
            _ = await thrownError { try await rig.manager.accessToken() }
        }
        #expect(
            Array(rig.levels(of: Self.requestFailed).dropFirst(Self.offline.count + 1))
                == Array(repeating: .warning, count: Self.notConnectivity.count))
    }

    @Test("Discovery: offline is a notice, a TLS failure a warning")
    func discovery() async throws {
        let rig = try await Rig()
        for (error, level) in [
            (URLError(.notConnectedToInternet), Logger.Level.notice), (URLError(.serverCertificateUntrusted), .warning),
        ] {
            rig.fail("/.well-known", with: error)
            let logs = LogCapture()
            _ = await thrownError {
                try await Discovery.fetchMetadata(
                    issuer: FakeAuthorizationServer.issuer, transport: rig.transport, logger: logs.logger)
            }
            #expect(logs.lines.filter { $0.message == Self.requestFailed }.map(\.level) == [level])
        }
    }

    @Test("Sign-out revocation: offline and a timeout are notices, other failures warnings")
    func revocation() async throws {
        for (error, level) in [
            (URLError(.notConnectedToInternet), Logger.Level.notice), (URLError(.serverCertificateUntrusted), .warning),
        ] {
            let rig = try await Rig()
            rig.fail("/revoke", with: error)
            let result = await rig.manager.signOut()
            guard case .failed = result.revocation else {
                Issue.record("expected a failed revocation")
                continue
            }
            #expect(rig.levels(of: Self.revocationFailed) == [level])
        }

        // The server answers with an error response.
        let rig = try await Rig()
        await rig.server.configure { $0.override = { $0.path == "/revoke" ? .init(status: 503, body: "") : nil } }
        _ = await rig.manager.signOut()
        #expect(rig.levels(of: Self.revocationFailed) == [.warning])

        // The request does not finish within the time limit.
        let slow = try await Rig()
        let gate = Gate()
        slow.transport.holding.update { $0["/revoke"] = gate }
        let signOut = Task { await slow.manager.signOut() }
        #expect(await slow.clock.waitForSleeper(timeout: .seconds(30)))
        slow.clock.advance(by: .seconds(10))
        #expect(await signOut.value.revocation == .timedOut)
        gate.open()
        #expect(slow.levels(of: "Revoking the refresh token timed out") == [.notice])
    }

    @Test("A revocation outcome is logged even when nobody reads the sign-out result")
    func revocationLoggedWithoutReader() async throws {
        let rig = try await Rig()
        rig.fail("/revoke", with: URLError(.notConnectedToInternet))
        _ = await rig.manager.beginSignOut()
        #expect(await waitUntil { rig.levels(of: Self.revocationFailed) == [.notice] })
    }

    @Test("A resource that rejects a renewed token again is a notice")
    func renewedTokenRejected() async throws {
        let rig = try await Rig()
        let resource = StaticTransport(status: 401, challenge: #"Bearer error="invalid_token""#)
        let authorizer = RequestAuthorizer(manager: rig.manager, transport: resource)
        let error = await thrownError {
            try await authorizer.send(HTTPRequest(method: .get, url: URL(string: "https://api.example.com/items")!))
        }
        #expect(error?.code == .unauthorized)
        #expect(rig.levels(of: "The resource rejected a renewed access token") == [.notice])
    }

    @Test("The failure lines carry no token")
    func noSecretInFailureLines() async throws {
        let rig = try await Rig()
        let credential = try #require(await rig.manager.credential)
        let secrets = [try #require(credential.refreshToken).reveal()]
        rig.fail("/token", with: URLError(.notConnectedToInternet))
        rig.wallClock.advance(by: .seconds(100_000))
        _ = await thrownError { try await rig.manager.accessToken() }
        rig.fail("/revoke", with: URLError(.timedOut))
        _ = await rig.manager.signOut()
        #expect(!rig.levels(of: Self.revocationFailed).isEmpty)
        for secret in secrets { #expect(!rig.logs.renderings.contains { $0.contains(secret) }) }
    }

    private struct StaticTransport: HTTPTransport {
        let status: Int
        let challenge: String

        func send(_ request: HTTPRequest, body: Data?) async throws -> (HTTPResponse, Data) {
            (HTTPResponse(status: .init(code: status), headerFields: [.wwwAuthenticate: challenge]), Data())
        }
    }
}
