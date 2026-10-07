import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("RequestAuthorizer: bearer tokens at the resource server", .timeLimit(.minutes(1)))
struct RequestAuthorizerConformanceTests {
    private let resource = HTTPRequest(method: .get, url: URL(string: "https://api.example.com/items")!)

    private func resourceRequests(_ harness: Harness) async -> [RecordedRequest] {
        await harness.server.requests.filter { $0.url.host == "api.example.com" }
    }

    private func rejectAtResource(_ harness: Harness, challenge: String) async {
        await harness.server.configure {
            $0.override = { request in
                request.url.host == "api.example.com"
                    ? .init(status: 401, headers: ["WWW-Authenticate": challenge]) : nil
            }
        }
    }

    @Test("RFC 6750 §3.1: an expired token is refreshed and the request succeeds")
    func endToEnd() async throws {
        let harness = try await Harness()
        let authorizer = RequestAuthorizer(manager: harness.manager, transport: harness.server)
        let stale = try await harness.manager.accessToken()
        await harness.server.expire(token: stale.value.reveal())

        let response = try await authorizer.send(resource)
        #expect(response.statusCode == 200)
        #expect(await harness.tokenRequests(.refreshToken).count == 1)
        let sent = await resourceRequests(harness)
        #expect(sent.count == 2)
        #expect(sent[0].headers["Authorization"] == "Bearer \(stale.value.reveal())")
        let fresh = try await harness.manager.accessToken()
        #expect(fresh.value != stale.value)
        #expect(sent[1].headers["Authorization"] == "Bearer \(fresh.value.reveal())")
    }

    @Test("RFC 6750 §3.1: concurrent 401s for one token cause one refresh and each request retries once")
    func concurrentRejections() async throws {
        let harness = try await Harness()
        let authorizer = RequestAuthorizer(manager: harness.manager, transport: harness.server)
        let stale = try await harness.manager.accessToken()
        await harness.server.expire(token: stale.value.reveal())
        let request = resource

        let statuses = try await withThrowingTaskGroup(of: Int.self) { group in
            for _ in 0..<8 { group.addTask { try await authorizer.send(request).statusCode } }
            return try await group.reduce(into: []) { $0.append($1) }
        }
        #expect(statuses == Array(repeating: 200, count: 8))
        #expect(await harness.tokenRequests(.refreshToken).count == 1)
        let sent = await resourceRequests(harness)
        let withStale = sent.filter { $0.headers["Authorization"] == "Bearer \(stale.value.reveal())" }
        #expect(sent.count - withStale.count == 8, "each request succeeds exactly once with the new token")
    }

    @Test("RFC 6750 §3.1: a 401 after another caller refreshed retries with the new token, without a refresh")
    func lateRejection() async throws {
        let harness = try await Harness()
        let authorizer = RequestAuthorizer(manager: harness.manager)
        let (signed, stale) = try await authorizer.sign(resource)
        await harness.server.expire(token: stale.value.reveal())
        let rejection = try await harness.server.send(signed)
        #expect(rejection.statusCode == 401)

        // Another caller notices first and refreshes.
        await harness.manager.invalidate(stale)
        let fresh = try await harness.manager.accessToken()
        #expect(await harness.tokenRequests(.refreshToken).count == 1)

        let decision = await authorizer.evaluate(
            statusCode: rejection.statusCode, headers: rejection.headers, token: stale, attempt: 0)
        #expect(decision == .retry)
        let (retried, token) = try await authorizer.sign(resource)
        #expect(token.value == fresh.value)
        #expect(try await harness.server.send(retried).statusCode == 200)
        #expect(await harness.tokenRequests(.refreshToken).count == 1)
    }

    @Test("RFC 6750 §3.1: a 403 insufficient_scope is delivered and never refreshes")
    func forbidden() async throws {
        let harness = try await Harness()
        await harness.server.configure { $0.requiredScope = ["admin"] }
        let authorizer = RequestAuthorizer(manager: harness.manager, transport: harness.server)

        let response = try await authorizer.send(resource)
        #expect(response.statusCode == 403)
        #expect(response.headers["WWW-Authenticate"]?.contains("insufficient_scope") == true)
        #expect(await harness.tokenRequests(.refreshToken).isEmpty)
        #expect(await resourceRequests(harness).count == 1)
    }

    @Test("RFC 6750 §3.1: a 401 insufficient_scope fails without a refresh or a retry")
    func insufficientScope() async throws {
        let harness = try await Harness()
        await rejectAtResource(harness, challenge: #"Bearer error="insufficient_scope""#)
        let authorizer = RequestAuthorizer(manager: harness.manager, transport: harness.server)

        let error = await thrownError { try await authorizer.send(resource) }
        #expect(error?.code == .insufficientScope)
        #expect(error?.recovery == .resourceDenied)
        #expect(await harness.tokenRequests(.refreshToken).isEmpty)
        #expect(await resourceRequests(harness).count == 1)
        #expect(await harness.manager.credential != nil, "a resource-level failure never ends the session")
    }

    @Test("RFC 6750 §3.1: a second 401 fails after exactly one refresh and one retry")
    func persistentRejection() async throws {
        let harness = try await Harness()
        await rejectAtResource(harness, challenge: #"Bearer error="invalid_token""#)
        let authorizer = RequestAuthorizer(manager: harness.manager, transport: harness.server)

        let error = await thrownError { try await authorizer.send(resource) }
        #expect(error?.code == .unauthorized)
        #expect(error?.recovery == .resourceDenied)
        #expect(await resourceRequests(harness).count == 2)
        #expect(await harness.tokenRequests(.refreshToken).count == 1)
        #expect(await harness.manager.credential != nil)
    }

    @Test("RFC 6750 §2.1: with no token obtainable nothing is sent")
    func signedOut() async throws {
        let harness = try await Harness(signedIn: false)
        let transport = RecordingTransport()
        let authorizer = RequestAuthorizer(manager: harness.manager, transport: transport)

        let error = await thrownError { try await authorizer.send(resource) }
        #expect(error?.code == .notAuthenticated)
        #expect(await transport.requests.isEmpty)
    }

    @Test("RFC 6750 §2.1: only Bearer tokens are sent, compared case-insensitively")
    func tokenType() async throws {
        let harness = try await Harness(signedIn: false)
        let transport = RecordingTransport()
        let authorizer = RequestAuthorizer(manager: harness.manager, transport: transport)

        try await harness.manager.signIn(
            with: TokenResponse(
                accessToken: Secret("sender-constrained"), tokenType: "DPoP", expiresIn: .seconds(600),
                refreshToken: Secret("refresh")),
            requestedScope: ["read"])
        let error = await thrownError { try await authorizer.send(resource) }
        #expect(error?.code == .invalidConfiguration)
        #expect(await transport.requests.isEmpty)
        #expect(await harness.manager.credential != nil, "a configuration error does not end the session")

        try await harness.manager.signIn(
            with: TokenResponse(
                accessToken: Secret("plain"), tokenType: "bEaReR", expiresIn: .seconds(600),
                refreshToken: Secret("refresh")),
            requestedScope: ["read"])
        let (signed, _) = try await authorizer.sign(resource)
        #expect(signed.headers["Authorization"] == "Bearer plain")
    }

    @Test("RFC 6750 §5.3: a plain http URL fails before any token is requested")
    func insecureURL() async throws {
        let harness = try await Harness()
        let transport = RecordingTransport()
        let authorizer = RequestAuthorizer(manager: harness.manager, transport: transport)
        let request = HTTPRequest(method: .get, url: URL(string: "http://api.example.com/items")!)

        let error = await thrownError { try await authorizer.send(request) }
        #expect(error?.code == .invalidConfiguration)
        #expect(await transport.requests.isEmpty)
        #expect(await harness.tokenRequests(.refreshToken).isEmpty)
    }
}
