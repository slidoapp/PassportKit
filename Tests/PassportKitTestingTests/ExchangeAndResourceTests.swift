import Foundation
import HTTPTypes
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

    @Test("exchange with a refresh token subject rotates it and can issue a refresh token")
    func exchangeRotatesSubject() async throws {
        let fixture = Fixture([.app(rotates: true)])
        let signedIn = try await fixture.signIn()
        let reply = try await exchange(
            fixture, subject: signedIn.refreshToken, type: Self.refreshType,
            extra: [("requested_token_type", Self.refreshType), ("audience", "billing")])
        #expect(reply.status == 200)
        #expect(reply["issued_token_type"] == Self.refreshType)
        #expect(reply["token_type"] == "N_A")
        let rotated = reply.refreshToken
        #expect(!rotated.isEmpty && rotated != signedIn.refreshToken)
        #expect(reply.accessToken != rotated)
        #expect(try await fixture.refresh(signedIn.refreshToken).error == "invalid_grant")
        #expect(try await fixture.refresh(reply.accessToken).status == 200)
        let reuse = try await exchange(fixture, subject: signedIn.refreshToken, type: Self.refreshType)
        #expect(reuse.error == "invalid_grant")
        #expect(
            try await exchange(
                fixture, subject: signedIn.accessToken, type: Self.accessType,
                extra: [("requested_token_type", Self.refreshType)]
            ).error == "invalid_request")
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

    @Test("a resource without a host is an absolute URI (RFC 8707 §2)")
    func uriResource() async throws {
        let fixture = Fixture()
        let reply = try await fixture.token(
            [("grant_type", "client_credentials"), ("resource", "urn:example:api")], as: .basic("service", "s3cret"))
        #expect(reply.status == 200)
    }

    @Test("resource endpoint challenges follow RFC 6750")
    func resourceChallenges() async throws {
        let fixture = Fixture()
        let signedIn = try await fixture.signIn(scope: "read")

        let missing = try await fixture.api(nil)
        #expect(missing.statusCode == 401)
        #expect(missing.headerFields[.wwwAuthenticate] == "Bearer")

        let unknown = try await fixture.api("nope")
        #expect(unknown.statusCode == 401)
        #expect(unknown.headerFields[.wwwAuthenticate] == #"Bearer error="invalid_token""#)

        await fixture.server.configure { $0.requiredScope = ["write"] }
        let insufficient = try await fixture.api(signedIn.accessToken)
        #expect(insufficient.statusCode == 403)
        #expect(insufficient.headerFields[.wwwAuthenticate]?.contains(#"error="insufficient_scope""#) == true)

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

@Suite("Fake server: refresh token exchange for an audience client")
struct AudienceExchangeTests {
    static let exchangeType = "urn:ietf:params:oauth:grant-type:token-exchange"
    static let refreshType = "urn:ietf:params:oauth:token-type:refresh_token"

    static func audienceClient(rotates: Bool = true) -> FakeAuthorizationServer.ClientRegistration {
        .init(
            id: "partner", allowedGrants: [.refreshToken], scope: ["read", "write", "admin"],
            rotatesRefreshTokens: rotates, accessTokenLifetime: .seconds(60), refreshTokenLifetime: .seconds(7200))
    }

    static let bystander = FakeAuthorizationServer.ClientRegistration(id: "bystander", allowedGrants: [.refreshToken])

    func exchangeForPartner(_ fixture: Fixture, subject: String, audience: String = "partner") async throws -> Reply {
        try await fixture.token([
            ("grant_type", Self.exchangeType), ("subject_token", subject), ("subject_token_type", Self.refreshType),
            ("requested_token_type", Self.refreshType), ("audience", audience),
        ])
    }

    func refresh(_ fixture: Fixture, _ token: String, as client: String = "partner") async throws -> Reply {
        try await fixture.post(
            Fixture.tokenURL, [("grant_type", "refresh_token"), ("refresh_token", token)], as: .publicClient(client))
    }

    @Test("the derived refresh token belongs to the audience client and its own settings")
    func derivedTokenBelongsToAudience() async throws {
        let fixture = Fixture([.app(rotates: true), Self.audienceClient()])
        await fixture.server.configure { $0.scopePolicy = { _, _ in ["read"] } }
        let root = try await fixture.signIn()
        let derived = try await exchangeForPartner(fixture, subject: root.refreshToken)
        #expect(derived.status == 200)
        #expect(derived["issued_token_type"] == Self.refreshType)
        let details = try #require(await fixture.server.details(of: derived.accessToken))
        #expect(details.clientID == "partner")
        #expect(details.audience == ["partner"])
        #expect(details.scope == ["read"])
        #expect(details.subject == (await fixture.server.details(of: root.refreshToken))?.subject)

        let redeemed = try await refresh(fixture, derived.accessToken)
        #expect(redeemed.status == 200)
        #expect(redeemed.json["expires_in"] as? Int == 60)
        #expect(redeemed.refreshToken != derived.accessToken)  // the audience client rotates
        #expect(await fixture.server.details(of: redeemed.refreshToken)?.clientID == "partner")
        fixture.wallClock.advance(by: .seconds(7200))
        #expect(try await refresh(fixture, redeemed.refreshToken).error == "invalid_grant")
    }

    @Test("only the audience client can redeem the derived token")
    func boundToAudienceClient() async throws {
        let fixture = Fixture([.app(), Self.audienceClient(), Self.bystander])
        let root = try await fixture.signIn()
        let derived = try await exchangeForPartner(fixture, subject: root.refreshToken)
        #expect(try await fixture.refresh(derived.accessToken).error == "invalid_grant")
        #expect(try await refresh(fixture, derived.accessToken, as: "bystander").error == "invalid_grant")
        #expect(try await refresh(fixture, derived.accessToken).status == 200)
    }

    @Test("revoking either chain leaves the other one working")
    func chainsAreIndependent() async throws {
        let fixture = Fixture([.app(rotates: true), Self.audienceClient()])
        let root = try await fixture.signIn()
        let derived = try await exchangeForPartner(fixture, subject: root.refreshToken)
        let rotatedRoot = derived.refreshToken
        #expect(!rotatedRoot.isEmpty)

        // Rotating the subject chain does not touch the derived one; revoking the derived one spares the root.
        #expect(try await fixture.refresh(rotatedRoot).status == 200)
        await fixture.server.revoke(token: derived.accessToken)
        #expect(try await refresh(fixture, derived.accessToken).error == "invalid_grant")
        #expect(try await fixture.refresh(rotatedRoot).error == "invalid_grant")  // retired by the refresh above
        let signedIn = try await fixture.signIn()
        let second = try await exchangeForPartner(fixture, subject: signedIn.refreshToken)

        // And the other way round.
        await fixture.server.revoke(token: second.refreshToken)
        #expect(try await fixture.refresh(second.refreshToken).error == "invalid_grant")
        #expect(try await refresh(fixture, second.accessToken).status == 200)
    }

    @Test("an audience that is not a registered client keeps the requester's grant")
    func unregisteredAudience() async throws {
        let fixture = Fixture([.app(), Self.audienceClient()])
        let root = try await fixture.signIn()
        let derived = try await exchangeForPartner(fixture, subject: root.refreshToken, audience: "billing")
        #expect(await fixture.server.details(of: derived.accessToken)?.clientID == "app")
        await fixture.server.revoke(token: derived.accessToken)
        #expect(try await fixture.refresh(root.refreshToken).error == "invalid_grant")
    }

    @Test("an audience client that may not refresh is invalid_target")
    func audienceWithoutRefreshGrant() async throws {
        let fixture = Fixture()
        let root = try await fixture.signIn()
        let reply = try await exchangeForPartner(fixture, subject: root.refreshToken, audience: "service")
        #expect(reply.error == "invalid_target")
    }
}
