import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("Fake server: token exchange, resource indicators and the protected resource")
struct ExchangeAndResourceTests {
    static let exchangeType = "urn:ietf:params:oauth:grant-type:token-exchange"
    static let accessType = "urn:ietf:params:oauth:token-type:access_token"
    static let refreshType = "urn:ietf:params:oauth:token-type:refresh_token"

    func exchange(_ fixture: Fixture, subject: String, type: String, extra: [(String, String)] = []) async throws
        -> Reply
    {
        try await fixture.token(
            [("grant_type", Self.exchangeType), ("subject_token", subject), ("subject_token_type", type)] + extra)
    }

    @Test("exchange of an access token records audience and repeated resources")
    func exchangeAccessToken() async throws {
        let fixture = Fixture()
        let signedIn = try await fixture.signIn()
        let reply = try await exchange(
            fixture, subject: signedIn.accessToken, type: Self.accessType,
            extra: [
                ("audience", "billing"), ("resource", "https://api.example.com/a"),
                ("resource", "https://api.example.com/b"), ("scope", "read"),
            ])
        #expect(reply.status == 200)
        #expect(reply["issued_token_type"] == Self.accessType)
        #expect(reply.scope == ["read"])
        #expect(reply["refresh_token"] == nil)
        let details = try #require(await fixture.server.details(of: reply.accessToken))
        #expect(details.audience == ["billing"])
        #expect(details.resources.map(\.absoluteString) == ["https://api.example.com/a", "https://api.example.com/b"])
        let recorded = try #require(await fixture.server.requests.last)
        #expect(recorded.values("resource").count == 2)
    }

    @Test("exchange of a refresh token, and invalid subjects")
    func exchangeRefreshToken() async throws {
        let fixture = Fixture()
        let signedIn = try await fixture.signIn()
        let reply = try await exchange(fixture, subject: signedIn.refreshToken, type: Self.refreshType)
        #expect(reply.status == 200)
        #expect(reply.scope == ["read", "write"])
        #expect(try await exchange(fixture, subject: "bogus", type: Self.refreshType).error == "invalid_grant")
        #expect(
            try await exchange(fixture, subject: signedIn.refreshToken, type: Self.accessType).error == "invalid_grant")
        #expect(try await exchange(fixture, subject: signedIn.refreshToken, type: "urn:x:y").error == "invalid_request")
        #expect(
            try await exchange(
                fixture, subject: signedIn.refreshToken, type: Self.refreshType, extra: [("scope", "admin")]
            ).error == "invalid_scope")
        await fixture.server.expire(token: signedIn.accessToken)
        #expect(
            try await exchange(fixture, subject: signedIn.accessToken, type: Self.accessType).error == "invalid_grant")
    }

    @Test(
        "exchange for an unauthorized resource",
        arguments: [
            (FakeAuthorizationServer.ExchangeForUnauthorizedResource.accessDenied401, 401),
            (.narrowScope200, 200),
        ])
    func exchangeUnauthorized(_ behaviour: FakeAuthorizationServer.ExchangeForUnauthorizedResource, _ status: Int)
        async throws
    {
        let fixture = Fixture()
        await fixture.server.configure {
            $0.isResourceUnauthorized = { $0.path.hasPrefix("/denied") }
            $0.exchangeForUnauthorizedResource = behaviour
        }
        let signedIn = try await fixture.signIn()
        let reply = try await exchange(
            fixture, subject: signedIn.accessToken, type: Self.accessType,
            extra: [("resource", "https://api.example.com/denied/x")])
        #expect(reply.status == status)
        if status == 401 {
            #expect(reply.error == "access_denied")
        } else {
            #expect(reply.scope == ["none"])
        }
        let allowed = try await exchange(
            fixture, subject: signedIn.accessToken, type: Self.accessType,
            extra: [("resource", "https://api.example.com/ok")])
        #expect(allowed.status == 200)
        #expect(allowed.scope == ["read", "write"])
    }

    @Test(
        "refresh with an unauthorized resource",
        arguments: [
            (FakeAuthorizationServer.RefreshForUnauthorizedResource.narrowScope200, 200),
            (.invalidTarget400, 400),
        ])
    func refreshUnauthorized(_ behaviour: FakeAuthorizationServer.RefreshForUnauthorizedResource, _ status: Int)
        async throws
    {
        let fixture = Fixture()
        await fixture.server.configure {
            $0.isResourceUnauthorized = { $0.path.hasPrefix("/denied") }
            $0.refreshWithUnauthorizedResource = behaviour
        }
        let signedIn = try await fixture.signIn()
        let reply = try await fixture.refresh(
            signedIn.refreshToken, extra: [("resource", "https://api.example.com/denied/x")])
        #expect(reply.status == status)
        if status == 200 { #expect(reply.scope == ["none"]) } else { #expect(reply.error == "invalid_target") }
        #expect(try await fixture.refresh(signedIn.refreshToken).status == 200)
    }

    @Test("a malformed resource is invalid_target")
    func malformedResource() async throws {
        let fixture = Fixture()
        let reply = try await fixture.token(
            [("grant_type", "client_credentials"), ("resource", "https://api.example.com/x#frag")],
            as: .basic("service", "s3cret"))
        #expect(reply.error == "invalid_target")
    }

    @Test("resource endpoint challenges follow RFC 6750")
    func resourceChallenges() async throws {
        let fixture = Fixture()
        let signedIn = try await fixture.signIn(scope: "read")

        let missing = try await fixture.api(nil)
        #expect(missing.statusCode == 401)
        #expect(missing.headers["WWW-Authenticate"] == "Bearer")

        let unknown = try await fixture.api("nope")
        #expect(unknown.statusCode == 401)
        #expect(unknown.headers["WWW-Authenticate"] == #"Bearer error="invalid_token""#)

        await fixture.server.configure { $0.requiredScope = ["write"] }
        let insufficient = try await fixture.api(signedIn.accessToken)
        #expect(insufficient.statusCode == 403)
        #expect(insufficient.headers["WWW-Authenticate"]?.contains(#"error="insufficient_scope""#) == true)

        await fixture.server.configure { $0.requiredScope = ["read"] }
        #expect(try await fixture.api(signedIn.accessToken).statusCode == 200)

        await fixture.server.expire(token: signedIn.accessToken)
        #expect(try await fixture.api(signedIn.accessToken).statusCode == 401)
    }

    @Test("access tokens expire with the injected wall clock")
    func accessTokenExpiry() async throws {
        let fixture = Fixture()
        let signedIn = try await fixture.signIn()
        fixture.wallClock.advance(by: .seconds(899))
        #expect(try await fixture.api(signedIn.accessToken).statusCode == 200)
        fixture.wallClock.advance(by: .seconds(1))
        #expect(try await fixture.api(signedIn.accessToken).statusCode == 401)

        let second = try await fixture.signIn()
        await fixture.server.revoke(token: second.accessToken)
        #expect(try await fixture.api(second.accessToken).statusCode == 401)
        #expect(await fixture.server.revoked == [second.accessToken])
    }
}
