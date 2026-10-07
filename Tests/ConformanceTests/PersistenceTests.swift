import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("TokenManager: persistence and acceptance", .timeLimit(.minutes(1)))
struct PersistenceTests {
    @Test("invariant 3: the rotated refresh token is saved before the access token is returned")
    func persistBeforePublish() async throws {
        let harness = try await Harness()
        let before = await harness.storedRefreshToken()
        harness.expireAccessTokens()
        _ = try await harness.manager.accessToken()
        let stored = await harness.storedRefreshToken()
        #expect(stored != nil && stored != before)
        #expect(stored == (await harness.currentRefreshToken()))
    }

    @Test("invariant 3: a failing store does not fail the call; the credential stays in memory")
    func storageFailure() async throws {
        let memory = InMemoryCredentialStore()
        let harness = try await Harness(store: memory)
        let before = await harness.storedRefreshToken()
        await memory.failNextSaves(1)
        harness.expireAccessTokens()
        _ = try await harness.manager.accessToken()
        let inMemory = await harness.currentRefreshToken()
        #expect(inMemory != before)
        #expect(await harness.storedRefreshToken() == before, "the failed save must not have reached the store")
        #expect(
            await Harness.take(3, from: harness.events) == [
                .signedIn, .storageFailed, .refreshed(target: .default),
            ])

        // The next refresh spends the in-memory token, so the server does not see a reused one.
        harness.expireAccessTokens()
        _ = try await harness.manager.accessToken()
        #expect(await harness.tokenRequests(.refreshToken).count == 2)
        #expect(await harness.storedRefreshToken() == (await harness.currentRefreshToken()))
    }

    @Test("invariant 3: a refresh token exchange persists the rotated subject and returns the issued token")
    func exchangeRefreshTokenPersists() async throws {
        let harness = try await Harness()
        let before = await harness.storedRefreshToken()
        let response = try await harness.manager.exchangeRefreshToken(audience: "billing")
        #expect(response.issuedTokenType == .refreshToken)
        let issued = response.accessToken.reveal()
        #expect(await harness.server.details(of: issued)?.audience == ["billing"])
        let stored = await harness.storedRefreshToken()
        #expect(stored != before && stored != issued)
        #expect(stored == response.refreshToken?.reveal())
        // The rotated subject is the one the next operation spends.
        harness.expireAccessTokens()
        _ = try await harness.manager.accessToken()
        #expect(await harness.presentedRefreshTokens() == [before, stored].compactMap { $0 })
    }

    @Test("invariant 4: a 200 with narrowed scope is rejected, the rotated token is kept, the session survives")
    func underscopedResponse() async throws {
        let harness = try await Harness(policy: RequireAnyScope(["read"]))
        await harness.server.configure { $0.isResourceUnauthorized = { $0.path.hasPrefix("/denied") } }
        let before = await harness.storedRefreshToken()
        let target = TokenTarget(resources: [deniedResource])

        let error = await thrownError { try await harness.manager.accessToken(for: target) }
        #expect(error?.code == .tokenRejected)
        #expect(error?.recovery == .resourceDenied)
        #expect(await harness.manager.credential != nil)
        let stored = await harness.storedRefreshToken()
        #expect(stored != before, "the rotated refresh token of the rejected response must be persisted")
        #expect(stored == (await harness.currentRefreshToken()))
        #expect(
            await Harness.take(2, from: harness.events) == [
                .signedIn, .tokenRejected(target: target, grantedScope: ["none"]),
            ])

        // The useless token was not cached: asking again goes back to the server instead of looping on it.
        _ = await thrownError { try await harness.manager.accessToken(for: target) }
        #expect(await harness.tokenRequests(.refreshToken).count == 2)
        // An accessible resource still works on the persisted token.
        let allowed = try await harness.manager.accessToken(for: TokenTarget(resources: [apiA]))
        #expect(allowed.grantedScope == ["read", "write"])
    }

    @Test(
        "invariant 4: a denied exchange is a resource denial in both server behaviours, and never ends the session",
        arguments: [FakeAuthorizationServer.ExchangeForUnauthorizedResource.accessDenied401, .narrowScope200])
    func deniedExchange(behavior: FakeAuthorizationServer.ExchangeForUnauthorizedResource) async throws {
        let harness = try await Harness(policy: RequireAnyScope(["read"]))
        await harness.server.configure {
            $0.isResourceUnauthorized = { $0.path.hasPrefix("/denied") }
            $0.exchangeForUnauthorizedResource = behavior
        }
        let target = TokenTarget(method: .exchangeAccessToken, resources: [deniedResource])
        let error = await thrownError { try await harness.manager.accessToken(for: target) }
        #expect(error?.code == (behavior == .accessDenied401 ? .accessDenied : .tokenRejected))
        #expect(error?.recovery == .resourceDenied)
        #expect(await harness.manager.credential != nil)
        #expect(await harness.storedRefreshToken() != nil)
        // The root grant is untouched: the default token is still served without a refresh.
        _ = try await harness.manager.accessToken()
        #expect(await harness.tokenRequests(.refreshToken).isEmpty)
        // And an accessible resource can be exchanged.
        let allowed = try await harness.manager.accessToken(
            for: TokenTarget(method: .exchangeAccessToken, resources: [apiA]))
        #expect(allowed.grantedScope == ["read", "write"])
    }
}
