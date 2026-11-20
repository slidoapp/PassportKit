import Foundation
import PassportKit
import PassportKitTesting
import Testing

/// Reproduction: a grant without a refresh token serves its default access token until that token expires
/// (specification §9, invariant 5). Asking for any other refresh grant target, while the default token is
/// still fresh, ends the whole session with `.expiredWithoutRefreshToken`.
///
/// `accessToken(for:)` misses the cache for the new target and starts a refresh lane turn. The turn finds no
/// refresh token and ends the session (`OAuthSession+Lane.swift`, `spendRefreshToken`) without checking which
/// target asked or whether the default token has expired. The app loses a token that still works, and the
/// maintainer reads a sign-out reason that says something expired when nothing did.
///
/// The expectations inside `withKnownIssue` describe the behaviour the fix should produce. They fail today, so the
/// test passes while it records known issues. Once the defect is fixed, Swift Testing reports that no known
/// issue was recorded, and the wrapper can go.
@Suite("Reproduction: a target the grant cannot issue ends the session", .timeLimit(.minutes(1)))
struct UnissuableTargetReproductionTests {
    @Test("An uncached refresh grant target signs out a grant without a refresh token while its token is fresh")
    func uncachedTargetEndsTheSession() async throws {
        // The server issued no refresh token (RFC 6749 §5.1 makes it optional). The access token lives 900 s.
        let harness = try await Harness(signedIn: false)
        var response = try await harness.grant()
        response.refreshToken = nil
        try await harness.manager.signIn(with: response, requestedScope: ["read", "write"])
        let fresh = try await harness.manager.accessToken()
        #expect(fresh.value == response.accessToken)

        // The app asks for a token bound to one resource (RFC 8707). No time passes: the default token has
        // about 900 s left.
        let error = await thrownError {
            try await harness.manager.accessToken(for: .refreshGrant(resources: [apiA]))
        }

        // The target cannot be issued, and nothing was sent to the server for it.
        #expect(error != nil)
        #expect(await harness.tokenRequests(.refreshToken).isEmpty)

        await withKnownIssue("#25: the refresh lane ends the session without checking the target") {
            // Today the error is notAuthenticated with recovery reauthenticate, which tells the app to sign in.
            #expect(error?.recovery != .reauthenticate, "only the requested target failed")
            #expect(error?.code != .notAuthenticated, "the session is still authenticated")
            // Today the credential is gone and `.signedOut(reason: .expiredWithoutRefreshToken)` was emitted.
            #expect(await harness.manager.credential != nil, "the session survives")
            // Today this throws notAuthenticated, although the default token has not expired.
            let afterwards = try? await harness.manager.accessToken()
            #expect(afterwards?.value == fresh.value, "the default token still works")
        }
    }

    @Test("The sign-out reason claims an expiry that did not happen")
    func signOutReasonIsMisleading() async throws {
        let harness = try await Harness(signedIn: false)
        var response = try await harness.grant()
        response.refreshToken = nil
        try await harness.manager.signIn(with: response, requestedScope: ["read", "write"])
        let fresh = try await harness.manager.accessToken()

        _ = await thrownError { try await harness.manager.accessToken(for: .refreshGrant(scope: ["read"])) }

        // The wall clock has not moved, so the default token is far from expiry.
        let remaining = try #require(fresh.expiresAt).timeIntervalSince(harness.wallClock.now())
        #expect(remaining > 800)
        // A user sign-out closes the event sequence, so the next two events exist whether or not the defect is
        // fixed: today the second one is the unexpected session end, after the fix it is this sign-out.
        await harness.manager.beginSignOut(revoke: false)
        let events = await Harness.take(2, from: harness.events)
        withKnownIssue("#25: the session ends with a reason that names an expiry") {
            #expect(events == [.signedIn, .signedOut(reason: .userInitiated)])
        }
    }
}
