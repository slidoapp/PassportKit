import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("TokenManager: refresh token lane, coalescing and invalidation", .timeLimit(.minutes(1)))
struct LaneTests {
    @Test("invariant 1: refreshes and exchanges of the refresh token run one at a time, each on the latest token")
    func oneLane() async throws {
        let harness = try await Harness()
        let manager = harness.manager
        harness.expireAccessTokens()
        await harness.delayTokenResponses()
        let targets = [
            TokenTarget.default, TokenTarget.refreshGrant(resources: [apiA]),
            TokenTarget.refreshGrant(resources: [apiB]),
        ]
        let results = await withTaskGroup(of: Bool.self) { group in
            for index in 0..<10 {
                group.addTask { (try? await manager.accessToken(for: targets[index % 3])) != nil }
            }
            for audience in ["billing", "reports"] {
                group.addTask { (try? await manager.exchangeRefreshToken(audience: audience)) != nil }
            }
            await harness.deliverResponses(5)
            return await group.reduce(into: []) { $0.append($1) }
        }
        #expect(results.count == 12)
        #expect(results.allSatisfy { $0 })
        #expect(await harness.tokenRequests(.refreshToken).count == 3)
        #expect(await harness.tokenRequests(.tokenExchange).count == 2)
        let presented = await harness.presentedRefreshTokens()
        #expect(presented.count == 5)
        #expect(Set(presented).count == 5, "a refresh token was presented twice")
        #expect(await harness.gauge.peak == 1, "two requests were in flight at once")
        #expect(await harness.storedRefreshToken() == (await harness.currentRefreshToken()))
        #expect(await harness.storedRefreshToken() != presented.last)
    }

    @Test("invariant 2: concurrent callers of one target share one request; targets never share tokens")
    func coalescing() async throws {
        let harness = try await Harness()
        let manager = harness.manager
        harness.expireAccessTokens()
        await harness.delayTokenResponses()
        let tokens = try await withThrowingTaskGroup(of: AccessToken.self) { group in
            for _ in 0..<20 {
                group.addTask { try await manager.accessToken(for: TokenTarget.refreshGrant(resources: [apiA])) }
            }
            await harness.deliverResponses(1)
            return try await group.reduce(into: []) { $0.append($1) }
        }
        #expect(tokens.count == 20)
        #expect(Set(tokens.map(\.value)).count == 1)
        #expect(await harness.tokenRequests(.refreshToken).count == 1)

        let other = Task { try await manager.accessToken(for: TokenTarget.refreshGrant(resources: [apiB])) }
        await harness.deliverResponses(1)
        let tokenB = try await other.value
        #expect(tokenB.value != tokens[0].value)
        #expect(await harness.server.details(of: tokenB.value.reveal())?.resources == [apiB])
        #expect(await harness.server.details(of: tokens[0].value.reveal())?.resources == [apiA])
        // Asking again is served from the cache, per target.
        #expect(
            try await manager.accessToken(for: TokenTarget.refreshGrant(resources: [apiA])).value == tokens[0].value)
        #expect(await harness.tokenRequests(.refreshToken).count == 2)
    }

    @Test("invariant 10: ten concurrent 401s for one token cause one refresh")
    func invalidation() async throws {
        let harness = try await Harness()
        let manager = harness.manager
        let stale = try await manager.accessToken()
        let renewed = try await withThrowingTaskGroup(of: AccessToken.self) { group in
            for _ in 0..<10 {
                group.addTask {
                    await manager.invalidate(stale)
                    return try await manager.accessToken()
                }
            }
            return try await group.reduce(into: []) { $0.append($1) }
        }
        #expect(await harness.tokenRequests(.refreshToken).count == 1)
        #expect(Set(renewed.map(\.value)).count == 1)
        #expect(renewed[0].value != stale.value)
        #expect(renewed[0].generation != stale.generation)

        // A late report about the old token cannot discard the new one.
        await manager.invalidate(stale)
        #expect(try await manager.accessToken().value == renewed[0].value)
        #expect(await harness.tokenRequests(.refreshToken).count == 1)
    }
}
