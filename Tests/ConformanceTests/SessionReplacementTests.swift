import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("TokenManager: sign-in window, replaced sessions and grants without a refresh token", .timeLimit(.minutes(1)))
struct SessionReplacementTests {
    @Test("invariant 6: a caller during sign-in joins its token instead of refreshing with the grant's first token")
    func signInWindow() async throws {
        let store = GatedStore()
        let harness = try await Harness(store: store, signedIn: false)
        let manager = harness.manager
        let response = try await harness.grant()
        await store.hold(.save)
        let signIn = Task { try await manager.signIn(with: response, requestedScope: ["read", "write"]) }
        #expect(await waitUntil { await manager.credential != nil })
        let concurrent = Task { try await manager.accessToken() }
        await store.release(.save)
        try await signIn.value

        let token = try await concurrent.value
        #expect(token.value == response.accessToken)
        #expect(await harness.tokenRequests(.refreshToken).isEmpty, "the grant's first refresh token was spent")
        // The cached token is the one that was returned, not an older one published late.
        #expect(try await manager.accessToken() == token)
        #expect(await harness.tokenRequests(.refreshToken).isEmpty)
    }

    enum Ending: CaseIterable { case signIn, signOutThenSignIn }

    @Test(
        "invariant 6: a request of an ended session that never answers cannot block the next session",
        arguments: Ending.allCases)
    func hungRequestOfOldSession(ending: Ending) async throws {
        let harness = try await Harness()
        let manager = harness.manager
        let oldRefreshToken = try #require(await harness.currentRefreshToken())
        harness.expireAccessTokens()
        await harness.server.configure {
            $0.override = {
                $0.value("refresh_token") == oldRefreshToken
                    ? .init(status: 400, body: #"{"error":"invalid_grant"}"#, delay: .seconds(1000)) : nil
            }
        }
        let stale = Task { try await manager.accessToken() }
        await harness.clock.waitForSleeper()
        // A revocation queues behind the hung request on the old session's lane.
        let signOut = ending == .signOutThenSignIn ? Task { await manager.signOut(revoke: true) } : nil
        if signOut != nil { #expect(await waitUntil { await manager.credential == nil }) }
        let fresh = try await harness.signInAgain()
        harness.expireAccessTokens()

        let next = Task { try await manager.accessToken() }
        let isServed = await finishes(next)
        // Let everything finish whatever happened above.
        harness.clock.advance(by: .seconds(1000))
        _ = await signOut?.value
        _ = await stale.result
        #expect(isServed, "the new session waited for the old one")
        _ = try await next.value
        #expect(await harness.presentedRefreshTokens().contains(try #require(fresh.refreshToken).reveal()))
    }

    @Test("invariant 6: a caller waiting when the session was replaced gets a token of the new session")
    func waiterOfReplacedSession() async throws {
        let harness = try await Harness()
        let oldRefreshToken = try #require(await harness.currentRefreshToken())
        harness.expireAccessTokens()
        await harness.server.configure {
            $0.override = {
                $0.value("refresh_token") == oldRefreshToken
                    ? .init(status: 400, body: #"{"error":"invalid_grant"}"#, delay: .seconds(10)) : nil
            }
        }
        let waiter = Task { try await harness.manager.accessToken() }
        await harness.clock.waitForSleeper()
        let fresh = try await harness.signInAgain()
        harness.clock.advance(by: .seconds(10))

        #expect(try await waiter.value.value == fresh.accessToken)
        #expect(await harness.manager.credential != nil)
        #expect(await harness.presentedRefreshTokens() == [oldRefreshToken])
    }

    @Test("invariant 5: a grant without a refresh token ends the session when its access token expires")
    func grantWithoutRefreshToken() async throws {
        let harness = try await Harness(signedIn: false)
        var response = try await harness.grant()
        response.refreshToken = nil
        try await harness.manager.signIn(with: response, requestedScope: ["read", "write"])
        #expect(try await harness.manager.accessToken().value == response.accessToken)

        harness.expireAccessTokens()
        let error = await thrownError { try await harness.manager.accessToken() }
        #expect(error?.code == .notAuthenticated)
        #expect(error?.recovery == .reauthenticate)
        #expect(await harness.manager.credential == nil)
        #expect(await harness.storedRefreshToken() == nil)
        #expect(
            await Harness.take(2, from: harness.events) == [.signedIn, .signedOut(reason: .expiredWithoutRefreshToken)])
        #expect(await harness.tokenRequests(.refreshToken).isEmpty)
    }
}
