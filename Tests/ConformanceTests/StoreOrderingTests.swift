import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("TokenManager: store ordering, revocation and event order", .timeLimit(.minutes(1)))
struct StoreOrderingTests {
    enum RotatingOperation: CaseIterable { case refresh, exchange }

    @Test(
        "invariant 1: sign-out during a rotation revokes the token the rotation issued, not the one it replaced",
        arguments: RotatingOperation.allCases)
    func revokesRotatedToken(operation: RotatingOperation) async throws {
        let harness = try await Harness()
        let manager = harness.manager
        let original = try #require(await harness.currentRefreshToken())
        harness.expireAccessTokens()
        await harness.delayTokenResponses()
        let inFlight = Task {
            switch operation {
            case .refresh: _ = try await manager.accessToken()
            case .exchange: _ = try await manager.exchangeRefreshToken(audiences: ["billing"])
            }
        }
        await harness.clock.waitForSleeper()
        let signOut = Task { await manager.signOut() }
        #expect(await waitUntil { await manager.credential == nil })
        // The request sent before sign-out finishes; the revocation request is not delayed.
        await harness.deliverResponses(1)
        let result = await signOut.value
        _ = await thrownError { try await inFlight.value }

        #expect(result.revocation == .revoked)
        let revoked = await harness.server.requests(to: "/revoke").compactMap { $0.value("token") }
        let rotated = try #require(await harness.newestIssuedRefreshToken())
        #expect(rotated != original)
        #expect(revoked == [rotated], "the refresh token issued by the in-flight request stays valid")
    }

    @Test("invariant 3: a save that finishes after a later sign-out cannot bring the session back")
    func slowSaveDoesNotOutliveSignOut() async throws {
        let store = GatedStore()
        let harness = try await Harness(store: store)
        let manager = harness.manager
        harness.expireAccessTokens()
        await store.hold(.save)
        let refresh = Task { try await manager.accessToken() }
        #expect(await waitUntil { await store.suspendedCount(.save) == 1 })

        let signOut = Task { await manager.signOut(revoke: false) }
        #expect(await waitUntil { await manager.credential == nil })
        await store.release(.save)
        _ = await signOut.value
        _ = await thrownError { try await refresh.value }

        #expect(store.log.entries.suffix(2) == ["save", "delete"])
        #expect(try await store.load(harness.account) == nil, "the signed-out session was restored by a late save")
        #expect(try await Harness(store: store, signedIn: false).manager.load() == nil)
    }

    @Test("invariant 3: persist before publish: the access token is returned only after the store has the rotation")
    func tokenIsReturnedAfterTheSave() async throws {
        let store = GatedStore()
        let harness = try await Harness(store: store)
        let manager = harness.manager
        let before = await harness.storedRefreshToken()
        harness.expireAccessTokens()
        await store.hold(.save)
        let refresh = Task {
            let token = try await manager.accessToken()
            store.log.append("returned")
            return token
        }
        #expect(await waitUntil { await store.suspendedCount(.save) == 1 })
        #expect(await harness.storedRefreshToken() == before, "the save has not taken effect yet")
        await store.release(.save)
        _ = try await refresh.value

        #expect(store.log.entries.suffix(2) == ["save", "returned"])
        #expect(await harness.storedRefreshToken() == (await harness.currentRefreshToken()))
        #expect(await harness.storedRefreshToken() != before)
    }

    @Test("a failing delete is reported, the session is still cleared in memory, and the order of events holds")
    func failingDelete() async throws {
        let store = GatedStore()
        let harness = try await Harness(store: store)
        await store.failNextDeletes()
        let result = await harness.manager.signOut(revoke: false)
        #expect(result == SignOutResult(isStoredCredentialDeleted: false, revocation: .skipped))
        #expect(await harness.manager.credential == nil)
        #expect(
            await Harness.take(3, from: harness.events) == [
                .signedIn, .signedOut(reason: .userInitiated), .storageFailed,
            ])
        // What was not deleted comes back on the next launch: the report is how the application learns of it.
        #expect(try await store.load(harness.account) != nil)
    }

    @Test("events: a slow sign-out cannot report .signedOut after the sign-in that followed it")
    func signedOutIsNotReportedLate() async throws {
        let store = GatedStore()
        let harness = try await Harness(store: store)
        let manager = harness.manager
        let response = try await harness.grant()
        await store.hold(.delete)
        let signOut = Task { await manager.signOut(revoke: false) }
        #expect(await waitUntil { await manager.credential == nil })
        let signIn = Task { try await manager.signIn(with: response, requestedScope: ["read", "write"]) }
        #expect(await waitUntil { await manager.credential != nil })
        await store.release(.delete)
        _ = await signOut.value
        try await signIn.value

        #expect(
            await Harness.take(3, from: harness.events) == [.signedIn, .signedOut(reason: .userInitiated), .signedIn])
        #expect(await harness.storedRefreshToken() == response.refreshToken?.reveal(), "the new session is stored")
    }
}
