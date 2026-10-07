import Foundation
import Testing

@testable import PassportKit

@Suite("Token cache bounds")
struct TokenCacheTests {
    private let now = Date(timeIntervalSince1970: 1_000_000)

    private func target(_ index: Int) throws -> TokenTarget {
        .refreshGrant(resources: [try #require(URL(string: "https://api.example.com/\(index)"))])
    }

    private func token(_ index: Int, in cache: inout TokenCache, lifetime: TimeInterval = 3600) throws -> AccessToken {
        AccessToken(
            value: Secret("t\(index)"), tokenType: "Bearer", expiresAt: now.addingTimeInterval(lifetime),
            target: try target(index), generation: cache.nextGeneration())
    }

    @Test func dropsTheOldestTokensBeyondTheCapacity() throws {
        var cache = TokenCache()
        for index in 0..<(TokenCache.capacity + 10) { cache.store(try token(index, in: &cache), now: now) }
        #expect(cache.tokenCount == TokenCache.capacity)
        let minimum: TimeInterval = 60
        #expect(cache.usableToken(for: try target(0), now: now, minimumLifetime: minimum) == nil)
        #expect(cache.usableToken(for: try target(9), now: now, minimumLifetime: minimum) == nil)
        #expect(cache.usableToken(for: try target(10), now: now, minimumLifetime: minimum) != nil)
        #expect(cache.usableToken(for: try target(TokenCache.capacity + 9), now: now, minimumLifetime: minimum) != nil)
    }

    @Test func dropsExpiredTokensWhenAnotherIsStored() throws {
        var cache = TokenCache()
        for index in 0..<5 { cache.store(try token(index, in: &cache, lifetime: 10), now: now) }
        #expect(cache.tokenCount == 5)
        cache.store(try token(99, in: &cache), now: now.addingTimeInterval(11))
        #expect(cache.tokenCount == 1)
    }

    @Test func boundsAndExpiresRejections() throws {
        var cache = TokenCache()
        let error = PassportError(.tokenRejected)
        for index in 0..<(TokenCache.capacity + 10) {
            cache.reject(
                target: try target(index), error: error, until: now.addingTimeInterval(TimeInterval(100 + index)),
                now: now)
        }
        #expect(cache.rejectionCount == TokenCache.capacity)
        #expect(cache.rejection(for: try target(0), now: now) == nil)
        #expect(cache.rejection(for: try target(TokenCache.capacity + 9), now: now) != nil)
        cache.reject(
            target: try target(1000), error: error, until: now.addingTimeInterval(1000),
            now: now.addingTimeInterval(500))
        #expect(cache.rejectionCount == 1)
    }
}
