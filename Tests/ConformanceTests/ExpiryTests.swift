import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("TokenManager: expiry and derived tokens", .timeLimit(.minutes(1)))
struct ExpiryTests {
    @Test("invariant 8: a cached token is used until it has less than the minimum lifetime left")
    func minimumTokenLifetime() async throws {
        let harness = try await Harness()
        harness.wallClock.advance(by: .seconds(800))
        _ = try await harness.manager.accessToken()
        #expect(await harness.tokenRequests(.refreshToken).isEmpty, "100 seconds left is more than the 60 required")
        harness.wallClock.advance(by: .seconds(50))
        _ = try await harness.manager.accessToken()
        #expect(await harness.tokenRequests(.refreshToken).count == 1)
    }

    @Test("invariant 8: a response without expires_in uses the default lifetime, or is refreshed on every use")
    func missingLifetime() async throws {
        let body = #"{"access_token":"opaque","token_type":"Bearer"}"#
        for defaultLifetime in [nil, Duration.seconds(300)] {
            let harness = try await Harness(rotates: false, defaultTokenLifetime: defaultLifetime)
            await harness.server.configure {
                $0.override = { $0.value("grant_type") == "refresh_token" ? .init(status: 200, body: body) : nil }
            }
            harness.expireAccessTokens()
            let first = try await harness.manager.accessToken()
            _ = try await harness.manager.accessToken()
            #expect(first.expiresAt == defaultLifetime.map { _ in harness.wallClock.now().addingTimeInterval(300) })
            #expect(await harness.tokenRequests(.refreshToken).count == (defaultLifetime == nil ? 2 : 1))
            harness.wallClock.advance(by: .seconds(300))
            _ = try await harness.manager.accessToken()
            #expect(await harness.tokenRequests(.refreshToken).count == (defaultLifetime == nil ? 3 : 2))
        }
    }

    @Test("invariant 8: the subject is refreshed before an exchange when it expires within the minimum lifetime")
    func subjectBeforeExchange() async throws {
        let harness = try await Harness()
        let stale = try await harness.manager.accessToken()
        harness.wallClock.advance(by: .seconds(850))
        let target = TokenTarget(method: .exchangeAccessToken, resources: [apiA])
        let derived = try await harness.manager.accessToken(for: target)

        let grants = await harness.server.requests(to: "/token").compactMap { $0.value("grant_type") }
        #expect(grants.suffix(2) == ["refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange"])
        let subject = try await harness.manager.accessToken()
        #expect(subject.value != stale.value)
        let exchange = try #require(await harness.tokenRequests(.tokenExchange).last)
        #expect(exchange.value("subject_token") == subject.value.reveal())
        #expect(exchange.value("subject_token_type") == TokenTypeIdentifier.accessToken.rawValue)
        #expect(exchange.value("requested_token_type") == TokenTypeIdentifier.accessToken.rawValue)
        #expect(exchange.values("resource") == [apiA.absoluteString])
        #expect(await harness.server.details(of: derived.value.reveal())?.resources == [apiA])
    }

    @Test("invariant 8: a derived token never outlives its subject")
    func derivedExpiryIsCapped() async throws {
        let harness = try await Harness()
        let subject = try await harness.manager.accessToken()
        harness.wallClock.advance(by: .seconds(800))
        let derived = try await harness.manager.accessToken(
            for: TokenTarget(method: .exchangeAccessToken, resources: [apiA]))
        #expect(await harness.tokenRequests(.refreshToken).isEmpty)
        #expect(derived.expiresAt == subject.expiresAt)
    }

    @Test("invariant 9: a refresh_token in an access token exchange response is not the root grant and is ignored")
    func derivedTokensIgnoreRefreshToken() async throws {
        let harness = try await Harness()
        let before = await harness.storedRefreshToken()
        let body = """
            {"access_token":"derived","token_type":"Bearer","expires_in":900,"scope":"read",\
            "issued_token_type":"urn:ietf:params:oauth:token-type:access_token","refresh_token":"rogue"}
            """
        await harness.server.configure {
            $0.override = {
                $0.value("grant_type") == GrantType.tokenExchange.rawValue ? .init(status: 200, body: body) : nil
            }
        }
        let derived = try await harness.manager.accessToken(
            for: TokenTarget(method: .exchangeAccessToken, audiences: ["billing"]))
        #expect(derived.value.reveal() == "derived")
        #expect(await harness.currentRefreshToken() == before)
        #expect(await harness.storedRefreshToken() == before)
        // The real refresh token still works.
        _ = try await harness.manager.accessToken(for: TokenTarget(resources: [apiB]))
        #expect(await harness.presentedRefreshTokens() == [before].compactMap { $0 })
    }
}
