import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("TokenManager: a session seeded from a refresh token", .timeLimit(.minutes(1)))
struct SeededSessionTests {
    @Test("the first accessToken() refreshes with the seeded token and persists the rotation")
    func firstTokenIsRefreshed() async throws {
        let harness = try await Harness(signedIn: false)
        let grant = try await harness.grant()
        let seeded = try #require(grant.refreshToken)

        await harness.manager.signIn(refreshToken: seeded, grantedScope: ["read", "write"])
        #expect(await harness.tokenRequests(.refreshToken).isEmpty, "seeding must not contact the server")

        let token = try await harness.manager.accessToken()
        #expect(token.value != grant.accessToken, "no access token was cached by the seed")
        #expect(await harness.presentedRefreshTokens() == [seeded.reveal()])
        let rotated = try #require(await harness.storedRefreshToken())
        #expect(rotated != seeded.reveal())
        #expect(rotated == (await harness.newestIssuedRefreshToken()))
        // The refreshed token is cached now.
        #expect(try await harness.manager.accessToken() == token)
        #expect(await harness.tokenRequests(.refreshToken).count == 1)
    }

    @Test("the credential is persisted before the call returns, and the session emits .signedIn")
    func persistedWithEvents() async throws {
        let harness = try await Harness(signedIn: false)
        let grant = try await harness.grant()
        let seeded = try #require(grant.refreshToken)

        await harness.manager.signIn(refreshToken: seeded, grantedScope: ["read"], idToken: Secret("id-token"))
        let stored = try #require(try await harness.store.load(harness.account))
        #expect(stored.refreshToken == seeded)
        #expect(stored.idToken == Secret("id-token"))
        #expect(stored.grantedScope == ["read"])
        #expect(stored.clientID == "app")
        #expect(await harness.manager.credential == stored)
        #expect(await Harness.take(1, from: harness.events) == [.signedIn])
    }

    @Test("seeding supersedes a refresh of the old session that is still in flight")
    func supersedesInFlightOperation() async throws {
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
        try await harness.clock.waitForSleeper()

        let seeded = try #require(try await harness.grant().refreshToken)
        await manager.signIn(refreshToken: seeded, grantedScope: ["read", "write"])
        let next = Task { try await manager.accessToken() }
        #expect(await finishes(next), "the seeded session waited for the old one")

        harness.clock.advance(by: .seconds(1000))
        _ = await stale.result
        _ = try await next.value
        #expect(await manager.credential != nil, "the stale invalid_grant ended the seeded session")
        #expect(await harness.presentedRefreshTokens().contains(seeded.reveal()))
    }
}
