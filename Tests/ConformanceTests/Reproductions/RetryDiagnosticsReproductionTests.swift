import Foundation
import HTTPTypes
import PassportKit
import PassportKitTesting
import Testing

/// Reproduction: the log of a 401 retry cannot say which token the resource rejected, why the library decided to
/// retry, or whether the retry renewed the token or reused one that another caller had already renewed.
///
/// `ProtectedResourceClient.handleResponse` writes one constant line without metadata for an explicit
/// `invalid_token` and for a 401 without a Bearer error code alike. `OAuthSession.discard(_:)` drops a token only
/// when it is still cached, so a late 401 retries with the replacement, which is correct but leaves no trace.
/// `AccessToken.generation` identifies each token instance within the session, and no log line carries it. The
/// refresh token has no such identifier at all, and the session logs the same lines whether a refresh was caused by
/// a cache miss, a token close to expiry or a discard after a 401.
///
/// The expectations name the metadata keys `access_token_generation` and `trigger`, which are the names the
/// suggested fix proposes.
@Suite("Reproduction: retry and renewal decisions cannot be traced in the log", .timeLimit(.minutes(1)))
struct RetryDiagnosticsReproductionTests {
    private static let retryMessage = "The resource answered 401; retrying once with a new access token"
    private let resource = HTTPRequest(method: .get, url: URL(string: "https://api.example.com/items")!)

    /// A line as a maintainer would read it, with the metadata in a stable order.
    private static func render(_ line: LogLine) -> String {
        let metadata = line.metadata.map { "\($0.key)=\($0.value)" }.sorted().joined(separator: " ")
        return "\(line.level) \(line.message) [\(metadata)]"
    }

    /// The lines that one 401 with `challenge` produces, for a fresh session.
    private func linesOfOne401(challenge: String?) async throws -> [String] {
        let logs = LogCapture()
        let harness = try await Harness(logger: logs.logger)
        let authorizer = ProtectedResourceClient(session: harness.manager)
        let token = try await harness.manager.accessToken()
        let mark = logs.lines.count
        let headers: HTTPFields = challenge.map { [.wwwAuthenticate: $0] } ?? [:]
        let decision = await authorizer.handleResponse(statusCode: 401, headers: headers, token: token, attempt: 0)
        #expect(decision == .retry)
        return logs.lines(after: mark).map(Self.render)
    }

    @Test("An invalid_token challenge and a 401 without a Bearer error code log the same line")
    func retryTriggersLookTheSame() async throws {
        // The resource says the token is invalid (RFC 6750 §3.1).
        let invalidToken = try await linesOfOne401(challenge: #"Bearer error="invalid_token""#)
        // A gateway in front of the resource answers 401 without a challenge, for a reason that may have nothing
        // to do with the token. The library retries anyway, which is its documented policy.
        let unqualified = try await linesOfOne401(challenge: nil)

        #expect(invalidToken == ["notice \(Self.retryMessage) []"])
        withKnownIssue("#28: the retry line has no metadata, so the two triggers look the same") {
            #expect(invalidToken != unqualified)
        }
    }

    @Test("A late 401 reuses the token another caller renewed, and no line ties the decisions together")
    func lateRejectionCannotBeTraced() async throws {
        let logs = LogCapture()
        let harness = try await Harness(logger: logs.logger)
        let authorizer = ProtectedResourceClient(session: harness.manager)
        // Callers A and B sign one request each with the same token, and the server revokes it early.
        let (requestA, stale) = try await authorizer.addingToken(to: resource)
        let (requestB, _) = try await authorizer.addingToken(to: resource)
        await harness.server.expire(token: stale.value.reveal())
        let mark = logs.lines.count

        // B's 401 arrives first: B discards the token and its retry renews it.
        let (rejectionB, _) = try await harness.server.send(requestB, body: nil)
        _ = await authorizer.handleResponse(
            statusCode: rejectionB.status.code, headers: rejectionB.headerFields, token: stale, attempt: 0)
        let (_, renewed) = try await authorizer.addingToken(to: resource)
        // A's 401 arrives after the renewal: the discard finds a newer token and A's retry reuses it.
        let (rejectionA, _) = try await harness.server.send(requestA, body: nil)
        _ = await authorizer.handleResponse(
            statusCode: rejectionA.status.code, headers: rejectionA.headerFields, token: stale, attempt: 0)
        let (_, reused) = try await authorizer.addingToken(to: resource)

        // The library did the right thing: one refresh, and both retries carry the renewed token.
        #expect(reused == renewed)
        #expect(await harness.tokenRequests(.refreshToken).count == 1)
        let lines = logs.lines(after: mark)
        let retries = lines.filter { $0.message == Self.retryMessage }
        #expect(retries.count == 2)

        let rendered = lines.map(Self.render)
        let rejectedGenerations = retries.map { $0.value("access_token_generation") }
        let mentionedGenerations = Set(lines.compactMap { $0.value("access_token_generation") })
        withKnownIssue("#28: retry lines carry no token identity and no outcome") {
            // B's decision discarded the token and A's found it already replaced; today both lines are equal.
            #expect(Set(retries.map(Self.render)).count == 2, "the two decisions can be told apart in \(rendered)")
            // Each retry line names the token instance the resource rejected.
            #expect(rejectedGenerations == ["\(stale.generation)", "\(stale.generation)"])
            // Some line names the token instance that the retries used.
            #expect(mentionedGenerations.contains("\(renewed.generation)"))
        }
    }

    @Test("A refresh for an expiring token and a refresh after a 401 discard log the same lines")
    func refreshTriggersLookTheSame() async throws {
        let expiring = LogCapture()
        let expiringHarness = try await Harness(logger: expiring.logger)
        expiringHarness.expireAccessTokens()
        let expiringMark = expiring.lines.count
        _ = try await expiringHarness.manager.accessToken()

        let discarded = LogCapture()
        let discardedHarness = try await Harness(logger: discarded.logger)
        await discardedHarness.manager.discard(try await discardedHarness.manager.accessToken())
        let discardedMark = discarded.lines.count
        _ = try await discardedHarness.manager.accessToken()

        let afterExpiry = expiring.lines(after: expiringMark).map(Self.render)
        let afterDiscard = discarded.lines(after: discardedMark).map(Self.render)
        #expect(afterExpiry.contains { $0.contains("Refresh token rotated") })
        withKnownIssue("#28: a refresh logs no trigger, so its reason is lost") {
            #expect(afterExpiry != afterDiscard)
        }
    }
}
