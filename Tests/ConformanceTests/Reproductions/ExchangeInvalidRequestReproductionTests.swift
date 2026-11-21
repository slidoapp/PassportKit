import Foundation
import PassportKit
import PassportKitTesting
import Testing

/// Reproduction: RFC 8693 §2.2.2 tells an authorization server to answer `invalid_request` when the exchange
/// request is malformed, when the subject or actor token is invalid for any reason, and when a token is
/// unacceptable under its policy. PassportKit maps every `invalid_request` to recovery `.fixConfiguration`
/// (`PassportError+Classification.swift`), so a revoked subject token reads as a configuration bug.
///
/// The session drops a rejected exchange subject from its cache only on `invalid_grant`
/// (`OAuthSession+Targets.swift`, `issueByExchange`). That is the code the fake server uses for an expired or
/// revoked subject, so the standard answer is untested. A standards-compliant server that rejects the cached
/// default token with `invalid_request` sees the same token again on every following exchange, until the client's
/// own clock says the token expired.
@Suite("Reproduction: an exchange rejected with invalid_request", .timeLimit(.minutes(1)))
struct ExchangeInvalidRequestReproductionTests {
    private static let target = TokenTarget.tokenExchange(audiences: ["reports"])

    /// Makes the server reject `subject` as an exchange subject with `code`, the way RFC 8693 §2.2.2 describes,
    /// although the client still holds it as a fresh default token: the server revoked it early, for example
    /// after a password change.
    private func rejectSubject(_ subject: String, with code: String, on harness: Harness) async {
        await harness.server.configure {
            $0.override = { request in
                guard request.value("grant_type") == GrantType.tokenExchange.rawValue,
                    request.value("subject_token") == subject
                else { return nil }
                return .init(
                    status: 400, body: #"{"error":"\#(code)","error_description":"The subject token is not active."}"#)
            }
        }
    }

    @Test("A subject rejected with invalid_request reads as a configuration bug and is offered again")
    func invalidRequestKeepsTheSubject() async throws {
        let harness = try await Harness()
        let subject = try await harness.manager.accessToken()
        await rejectSubject(subject.value.reveal(), with: "invalid_request", on: harness)

        let first = await thrownError { try await harness.manager.accessToken(for: Self.target) }
        _ = await thrownError { try await harness.manager.accessToken(for: Self.target) }

        #expect(first?.code == .invalidRequest)
        // These hold today and must keep holding: invalid_request alone is no reason to refresh or sign out.
        #expect(await harness.manager.credential != nil)
        #expect(await harness.tokenRequests(.refreshToken).isEmpty)

        let offers = await harness.tokenRequests(.tokenExchange).filter {
            $0.value("subject_token") == subject.value.reveal()
        }
        withKnownIssue("#26: every invalid_request is fixConfiguration, and only invalid_grant evicts the subject") {
            // Today: fixConfiguration, which says the app is misconfigured and retrying cannot help.
            #expect(first?.recovery != .fixConfiguration, "the cause may be the subject token or the policy")
            // Today: 2, the second call sends the rejected subject again.
            #expect(offers.count == 1, "a rejected subject is not offered again right away")
        }
    }

    @Test("For comparison: invalid_grant evicts the subject, so the next exchange refreshes it first")
    func invalidGrantEvictsTheSubject() async throws {
        let harness = try await Harness()
        let subject = try await harness.manager.accessToken()
        await rejectSubject(subject.value.reveal(), with: "invalid_grant", on: harness)

        let first = await thrownError { try await harness.manager.accessToken(for: Self.target) }
        let second = try await harness.manager.accessToken(for: Self.target)

        // invalid_grant on an access token subject does not end the session (ErrorResponseContext.other).
        #expect(first?.code == .invalidGrant)
        #expect(first?.recovery == .noAction)
        #expect(await harness.tokenRequests(.refreshToken).count == 1)
        let subjects = await harness.tokenRequests(.tokenExchange).map { $0.value("subject_token") }
        #expect(subjects.count == 2)
        #expect(subjects.last != subject.value.reveal())
        #expect(second.target == Self.target)
    }
}
