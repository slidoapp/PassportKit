import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("TokenManager: event buffering, cancelled sign-out and target identity", .timeLimit(.minutes(1)))
struct EventAndTargetTests {
    @Test("events: a subscriber that does not read keeps the newest 64 events, not all of them")
    func boundedEventBuffer() async throws {
        let harness = try await Harness(signedIn: false)
        let response = try await harness.grant()
        let stream = harness.manager.events
        for _ in 0..<70 { try await harness.manager.signIn(with: response, requestedScope: ["read", "write"]) }
        _ = await harness.manager.signOut(revoke: false)

        let events = await Harness.take(64, from: stream)
        #expect(events.last == .signedOut(reason: .userInitiated), "the newest event was dropped")
        #expect(events.dropLast().allSatisfy { $0 == .signedIn })
    }

    @Test("signOut: cancelling the caller reports .cancelled, not a timeout, and still clears the session")
    func cancelledSignOut() async throws {
        let harness = try await Harness()
        await harness.server.configure {
            $0.override = { $0.path == "/revoke" ? .init(status: 200, delay: .seconds(60)) : nil }
        }
        let signOut = Task { await harness.manager.signOut() }
        // The wait limit, the request limit and the server's own delay.
        #expect(await waitUntil { harness.clock.sleeperCount >= 3 })
        signOut.cancel()
        let result = await signOut.value

        #expect(result == SignOutResult(isStoredCredentialDeleted: true, revocation: .cancelled))
        #expect(await harness.manager.credential == nil)
        #expect(await harness.storedRefreshToken() == nil)
        harness.clock.advance(by: .seconds(60))
    }

    @Test("a target is the same whatever the order or repetition of its resources and audiences")
    func targetIdentity() {
        let reordered = TokenTarget.refreshGrant(resources: [apiB, apiA, apiB], scope: ["read", "write"])
        let target = TokenTarget.refreshGrant(resources: [apiA, apiB], scope: ["write", "read"])
        #expect(reordered == target)
        #expect(Set([reordered, target]).count == 1)
        let exchange = TokenTarget.exchange(audiences: ["a", "b"])
        #expect(exchange == TokenTarget.exchange(audiences: ["b", "a", "a"]))
        #expect(exchange != TokenTarget(derivation: .refreshGrant, audiences: ["a", "b"]))
        #expect(TokenTarget.refreshGrant(resources: [apiA]) != TokenTarget.refreshGrant(resources: [apiA, apiB]))
        // No scope asked for and an empty scope asked for are different requests.
        #expect(TokenTarget.refreshGrant(scope: nil) != TokenTarget.refreshGrant(scope: ScopeSet([])))
    }

    @Test("invariant 2: callers that list the same resources in another order share one request and one token")
    func targetsInAnyOrderCoalesce() async throws {
        let harness = try await Harness()
        let manager = harness.manager
        harness.expireAccessTokens()
        await harness.delayTokenResponses()
        let orders = [[apiA, apiB], [apiB, apiA], [apiA, apiB, apiA]]
        let tokens = try await withThrowingTaskGroup(of: AccessToken.self) { group in
            for resources in orders {
                group.addTask { try await manager.accessToken(for: TokenTarget.refreshGrant(resources: resources)) }
            }
            await harness.deliverResponses(1)
            return try await group.reduce(into: []) { $0.append($1) }
        }
        #expect(Set(tokens.map(\.value)).count == 1)
        #expect(await harness.tokenRequests(.refreshToken).count == 1)
        #expect(
            try await manager.accessToken(for: TokenTarget.refreshGrant(resources: [apiB, apiA])).value
                == tokens[0].value)
        #expect(await harness.tokenRequests(.refreshToken).count == 1)
    }
}
