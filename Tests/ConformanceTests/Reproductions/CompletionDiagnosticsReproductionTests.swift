import Foundation
import Logging
import PassportKit
import PassportKitTesting
import Testing

/// Reproduction: the diagnostics record HTTP completion and never the OAuth result of the same operation.
///
/// `OAuthClient.send(_:)` and `Discovery.fetchMetadata` log "Request completed" and emit
/// `RequestEvent.response` as soon as the HTTP response arrives, before the body is decoded, the metadata issuer is
/// checked or the token response is parsed. A failure in any of those steps throws a typed error and records
/// nothing, so the last diagnostic of a failed operation is a 200. The session logs "Refresh token rotated" before
/// the save of the rotated token finishes, so the log claims a rotation that the store may never hold.
@Suite("Reproduction: a 200 is the last diagnostic of a failed operation", .timeLimit(.minutes(1)))
struct CompletionDiagnosticsReproductionTests {
    @Test("Discovery records a completed 200 and nothing else when the metadata fails the issuer check")
    func discoveryIssuerMismatch() async throws {
        let server = FakeAuthorizationServer(clients: [])
        // A common deployment mistake: the metadata names the issuer with a trailing slash. RFC 8414 §3.3
        // requires the identical string, so this is a mismatch.
        await server.configure { $0.advertisedIssuer = "https://as.example.com/" }
        let events = EventLog()
        let logs = LogCapture()

        let error = await thrownError {
            try await Discovery.fetchMetadata(
                issuer: FakeAuthorizationServer.issuer, transport: server, observer: events, logger: logs.logger)
        }

        #expect(error?.code == .issuerMismatch)
        // Everything the maintainer sees today: one completed request with status 200.
        #expect(logs.lines.map(\.message) == ["Request completed"])
        #expect(logs.lines.first?.value("status") == "200")
        #expect(events.all.count == 2)
        guard case .response(.metadata, 200, nil, _)? = events.all.last else {
            Issue.record("unexpected events \(events.all)")
            return
        }

        let code = PassportError.Code.issuerMismatch.rawValue
        let loggedCodes = logs.lines.compactMap { $0.value("error_code") }
        let reportedEvents = events.all.map { "\($0)" }
        withKnownIssue("#27: discovery logs before it validates, and reports no validation result") {
            #expect(loggedCodes.contains(code), "log line")
            #expect(reportedEvents.contains { $0.contains(code) }, "RequestEvent in \(reportedEvents)")
        }
    }

    @Test("A token response that fails parsing is logged as a completed 200")
    func malformedExchangeResponse() async throws {
        let logs = LogCapture()
        let harness = try await Harness(logger: logs.logger)
        // RFC 8693 §2.2.1 requires `issued_token_type`; a response without it is invalid (XCH-4).
        await harness.server.configure {
            $0.override = { request in
                request.value("grant_type") == GrantType.tokenExchange.rawValue
                    ? .init(status: 200, body: #"{"access_token":"exchanged","token_type":"Bearer"}"#) : nil
            }
        }
        let mark = logs.lines.count

        let error = await thrownError {
            try await harness.manager.accessToken(for: .tokenExchange(audiences: ["reports"]))
        }

        #expect(error?.code == .invalidResponse)
        let lines = logs.lines(after: mark)
        let completed = lines.filter { $0.message == "Request completed" }
        #expect(completed.map { $0.value("status") } == ["200"])
        #expect(completed.first?.value("grant_type") == GrantType.tokenExchange.rawValue)

        let loggedCodes = lines.compactMap { $0.value("error_code") }
        withKnownIssue("#27: token requests log before parsing, and nothing records the failure") {
            #expect(loggedCodes.contains(PassportError.Code.invalidResponse.rawValue))
        }
    }

    @Test("Refresh token rotated is logged while the store still holds the spent token")
    func rotationLoggedBeforeSave() async throws {
        let logs = LogCapture()
        let store = GatedStore()
        let harness = try await Harness(store: store, logger: logs.logger)
        let spent = try #require(await harness.storedRefreshToken())
        harness.expireAccessTokens()
        await store.hold(.save)

        let refresh = Task { try await harness.manager.accessToken() }
        #expect(await waitUntil { await store.suspendedCount(.save) == 1 })

        // The server rotated the token, so `spent` is now a reused token at the server. The store still holds
        // it: an app that is killed now restores it on the next launch and the server rejects it.
        #expect(await harness.storedRefreshToken() == spent)
        let claimedBeforeSave = logs.contains("Refresh token rotated", level: .info)
        await store.release(.save)
        _ = try await refresh.value
        #expect(await harness.storedRefreshToken() != spent)

        withKnownIssue("#27: the rotation is logged before the save, without its outcome") {
            #expect(!claimedBeforeSave)
        }
    }
}
