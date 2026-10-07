import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("TokenManager: session end, generations, cancellation and sign-out", .timeLimit(.minutes(1)))
struct LifecycleTests {
    @Test("invariant 5: a rejected refresh token ends the session")
    func refreshTokenRejected() async throws {
        let harness = try await Harness()
        let refreshToken = try #require(await harness.currentRefreshToken())
        await harness.server.revoke(token: refreshToken)
        harness.expireAccessTokens()

        let error = await thrownError { try await harness.manager.accessToken() }
        #expect(error?.code == .invalidGrant)
        #expect(error?.recovery == .reauthenticate)
        #expect(await harness.manager.credential == nil)
        #expect(await harness.storedRefreshToken() == nil)
        #expect(await Harness.take(2, from: harness.events) == [.signedIn, .signedOut(reason: .refreshTokenRejected)])
        #expect(await thrownError { try await harness.manager.accessToken() }?.code == .notAuthenticated)
        #expect(
            await thrownError { try await harness.manager.exchangeRefreshToken(audience: "a") }?.code
                == .notAuthenticated)
    }

    @Test("invariant 6: a stale invalid_grant cannot end a session that replaced the one it was for")
    func staleRefreshAfterSignIn() async throws {
        let harness = try await Harness()
        let oldRefreshToken = try #require(await harness.currentRefreshToken())
        harness.expireAccessTokens()
        await harness.server.configure {
            $0.override = {
                $0.value("refresh_token") == oldRefreshToken
                    ? .init(status: 400, body: #"{"error":"invalid_grant"}"#, delay: .seconds(10)) : nil
            }
        }
        let stale = Task { try await harness.manager.accessToken() }
        await harness.clock.waitForSleeper()
        let fresh = try await harness.signInAgain()
        harness.clock.advance(by: .seconds(10))

        #expect(await thrownError { try await stale.value }?.code == .notAuthenticated)
        let freshRefreshToken = fresh.refreshToken?.reveal()
        #expect(await harness.currentRefreshToken() == freshRefreshToken)
        #expect(await harness.storedRefreshToken() == freshRefreshToken)
        // The new session works, on its own refresh token.
        harness.expireAccessTokens()
        _ = try await harness.manager.accessToken()
        #expect(await harness.presentedRefreshTokens() == [oldRefreshToken, freshRefreshToken].compactMap { $0 })
        #expect(await harness.storedRefreshToken() != freshRefreshToken)
    }

    @Test("invariant 6: a refresh that completes after sign-out discards its result and writes nothing")
    func refreshAfterSignOut() async throws {
        let harness = try await Harness()
        harness.expireAccessTokens()
        await harness.delayTokenResponses()
        let inFlight = Task { try await harness.manager.accessToken() }
        await harness.clock.waitForSleeper()

        let result = await harness.manager.signOut(revoke: false)
        #expect(result == SignOutResult(isStoredCredentialDeleted: true, revocation: .skipped))
        harness.clock.advance(by: .seconds(10))

        #expect(await thrownError { try await inFlight.value }?.code == .notAuthenticated)
        #expect(await harness.manager.credential == nil)
        #expect(await harness.storedRefreshToken() == nil, "a discarded result must not be written back")
        #expect(await thrownError { try await harness.manager.accessToken() }?.code == .notAuthenticated)
    }

    @Test("invariant 7: cancelling the only waiter does not cancel the request or lose the rotated token")
    func cancellation() async throws {
        let harness = try await Harness()
        let before = try #require(await harness.currentRefreshToken())
        harness.expireAccessTokens()
        await harness.delayTokenResponses()
        let waiter = Task { try await harness.manager.accessToken() }
        await harness.clock.waitForSleeper()
        waiter.cancel()
        await #expect(throws: CancellationError.self) { try await waiter.value }
        harness.clock.advance(by: .seconds(10))

        // Another target queues behind the finished request, so it must see the rotated token.
        let next = Task { try await harness.manager.accessToken(for: TokenTarget(resources: [apiA])) }
        await harness.clock.waitForSleeper()
        harness.clock.advance(by: .seconds(10))
        _ = try await next.value

        let presented = await harness.presentedRefreshTokens()
        #expect(presented.count == 2 && presented[0] == before && presented[1] != before)
        #expect(await harness.storedRefreshToken() == (await harness.currentRefreshToken()))
        #expect(await harness.storedRefreshToken() != presented[1])
        // The abandoned request's token was still cached for whoever asks next.
        _ = try await harness.manager.accessToken()
        #expect(await harness.tokenRequests(.refreshToken).count == 2)
    }

    @Test("sign-out clears local state, then revokes the refresh token")
    func signOut() async throws {
        let harness = try await Harness()
        let refreshToken = try #require(await harness.currentRefreshToken())
        let result = await harness.manager.signOut()
        #expect(result == SignOutResult(isStoredCredentialDeleted: true, revocation: .revoked))
        #expect(await harness.server.revoked.contains(refreshToken))
        #expect(await harness.manager.credential == nil)
        #expect(await harness.storedRefreshToken() == nil)
        #expect(await Harness.take(2, from: harness.events) == [.signedIn, .signedOut(reason: .userInitiated)])
        #expect(await thrownError { try await harness.manager.accessToken() }?.code == .notAuthenticated)
        #expect(await harness.manager.signOut().revocation == .skipped)
    }

    @Test("sign-out clears local state even when revocation fails or hangs")
    func signOutWithBrokenRevocation() async throws {
        let failing = try await Harness()
        await failing.server.configure { $0.override = { $0.path == "/revoke" ? .init(status: 500) : nil } }
        let failed = await failing.manager.signOut()
        guard case .failed(let error) = failed.revocation else {
            Issue.record("Expected a failure")
            return
        }
        #expect(error.code == .temporarilyUnavailable)
        #expect(failed.isStoredCredentialDeleted)
        #expect(await failing.manager.credential == nil)

        let hanging = try await Harness()
        await hanging.server.configure {
            $0.override = { $0.path == "/revoke" ? .init(status: 200, delay: .seconds(60)) : nil }
        }
        let pending = Task { await hanging.manager.signOut() }
        // Three sleepers: the wait limit, the request limit and the server's own delay.
        while hanging.clock.sleeperCount < 3 { await Task.yield() }
        hanging.clock.advance(by: .seconds(5))
        #expect(await pending.value.revocation == .timedOut)
        #expect(await hanging.manager.credential == nil)
        #expect(await hanging.storedRefreshToken() == nil)
    }

    @Test("load restores a stored credential and ignores one for another client or issuer")
    func load() async throws {
        let harness = try await Harness(signedIn: false)
        let response = try await harness.grant()
        let credential = Credential(
            clientID: "app", issuer: FakeAuthorizationServer.issuer, refreshToken: response.refreshToken,
            updatedAt: harness.wallClock.now())
        for foreign in [
            Credential(
                clientID: "other", issuer: credential.issuer, refreshToken: credential.refreshToken,
                updatedAt: credential.updatedAt),
            Credential(
                clientID: "app", issuer: URL(string: "https://other.example.com"),
                refreshToken: credential.refreshToken, updatedAt: credential.updatedAt),
        ] {
            try await harness.store.save(foreign, for: harness.account)
            #expect(try await harness.manager.load() == nil)
            #expect(await harness.manager.credential == nil)
            #expect(try await harness.store.load(harness.account) == foreign, "an ignored credential is not deleted")
        }

        try await harness.store.save(credential, for: harness.account)
        #expect(try await harness.manager.load() == credential)
        #expect(await harness.manager.credential == credential)
        #expect(await Harness.take(1, from: harness.events) == [.signedIn])
        // Nothing is cached after a restart, so the first token is a refresh on the stored token.
        _ = try await harness.manager.accessToken()
        #expect(await harness.tokenRequests(.refreshToken).count == 1)
    }

    @Test("every subscriber receives every event, and streams end when the manager is released")
    func events() async throws {
        let harness = try await Harness()
        let first = harness.manager.events
        let second = harness.manager.events
        _ = await harness.manager.signOut(revoke: false)
        #expect(await Harness.take(1, from: first) == [.signedOut(reason: .userInitiated)])
        #expect(await Harness.take(1, from: second) == [.signedOut(reason: .userInitiated)])

        let stream = try await { () -> AsyncStream<SessionEvent> in
            let temporary = try await Harness(signedIn: false)
            return temporary.manager.events
        }()
        for await _ in stream {}
    }
}
