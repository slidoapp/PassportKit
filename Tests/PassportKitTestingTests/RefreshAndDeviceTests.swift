import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("Fake server: refresh, rotation, revocation and device grant")
struct RefreshAndDeviceTests {
    @Test("without rotation the refresh token stays valid and is not reissued")
    func refreshWithoutRotation() async throws {
        let fixture = Fixture()
        let signedIn = try await fixture.signIn()
        for _ in 0..<2 {
            let reply = try await fixture.refresh(signedIn.refreshToken)
            #expect(reply.status == 200)
            #expect(reply["refresh_token"] == nil)
            #expect(reply.scope == ["read", "write"])
        }
        let narrower = try await fixture.refresh(signedIn.refreshToken, extra: [("scope", "read")])
        #expect(narrower.scope == ["read"])
        let wider = try await fixture.refresh(signedIn.refreshToken, extra: [("scope", "admin")])
        #expect(wider.error == "invalid_scope")
    }

    @Test("rotation retires the old refresh token")
    func rotation() async throws {
        let fixture = Fixture([.app(rotates: true)])
        let signedIn = try await fixture.signIn()
        let rotated = try await fixture.refresh(signedIn.refreshToken)
        #expect(rotated.status == 200)
        #expect(!rotated.refreshToken.isEmpty)
        #expect(rotated.refreshToken != signedIn.refreshToken)
        let reuse = try await fixture.refresh(signedIn.refreshToken)
        #expect(reuse.status == 400)
        #expect(reuse.error == "invalid_grant")
        #expect(try await fixture.refresh(rotated.refreshToken).status == 200)
    }

    @Test("a retired token works once inside the leeway, then never again")
    func rotationLeeway() async throws {
        let fixture = Fixture([.app(rotates: true, leeway: .init(window: .seconds(120), maximumReuse: 1))])
        let signedIn = try await fixture.signIn()
        let rotated = try await fixture.refresh(signedIn.refreshToken)
        fixture.wallClock.advance(by: .seconds(60))
        let reused = try await fixture.refresh(signedIn.refreshToken)
        #expect(reused.status == 200)
        #expect(reused.refreshToken == rotated.refreshToken)
        #expect(try await fixture.refresh(signedIn.refreshToken).error == "invalid_grant")
        #expect(try await fixture.refresh(rotated.refreshToken).status == 200)
    }

    @Test("a retired token is refused after the leeway window")
    func leewayExpires() async throws {
        let fixture = Fixture([.app(rotates: true, leeway: .init(window: .seconds(120), maximumReuse: 1))])
        let signedIn = try await fixture.signIn()
        _ = try await fixture.refresh(signedIn.refreshToken)
        fixture.wallClock.advance(by: .seconds(121))
        #expect(try await fixture.refresh(signedIn.refreshToken).error == "invalid_grant")
    }

    @Test("reuse can revoke the whole grant")
    func reuseRevokesGrant() async throws {
        let fixture = Fixture([.app(rotates: true, revokesGrantOnReuse: true)])
        let signedIn = try await fixture.signIn()
        let rotated = try await fixture.refresh(signedIn.refreshToken)
        #expect(try await fixture.refresh(signedIn.refreshToken).error == "invalid_grant")
        #expect(try await fixture.refresh(rotated.refreshToken).error == "invalid_grant")
        #expect(try await fixture.api(rotated.accessToken).statusCode == 401)
    }

    @Test("refresh token lifetime and revocation")
    func refreshLifetime() async throws {
        let fixture = Fixture([.app(refreshLifetime: .seconds(100))])
        let first = try await fixture.signIn()
        fixture.wallClock.advance(by: .seconds(101))
        #expect(try await fixture.refresh(first.refreshToken).error == "invalid_grant")

        let second = try await fixture.signIn()
        let revoked = try await fixture.post(
            FakeAuthorizationServer.revocationEndpoint, [("token", second.refreshToken)])
        #expect(revoked.status == 200)
        #expect(try await fixture.refresh(second.refreshToken).error == "invalid_grant")
        #expect(try await fixture.api(second.accessToken).statusCode == 401)
        #expect(await fixture.server.revoked.contains(second.refreshToken))
        let unknown = try await fixture.post(FakeAuthorizationServer.revocationEndpoint, [("token", "nope")])
        #expect(unknown.status == 200)
    }

    @Test("refresh by another client is refused")
    func refreshOtherClient() async throws {
        let other = FakeAuthorizationServer.ClientRegistration(id: "other", allowedGrants: [.refreshToken])
        let fixture = Fixture([.app(), other])
        let signedIn = try await fixture.signIn()
        let reply = try await fixture.token(
            [("grant_type", "refresh_token"), ("refresh_token", signedIn.refreshToken)], as: .publicClient("other"))
        #expect(reply.error == "invalid_grant")
    }

    @Test("device grant: pending, slow_down, approval, single use")
    func deviceApproval() async throws {
        let fixture = Fixture()
        let started = try await fixture.startDevice()
        #expect(started.status == 200)
        let deviceCode = try #require(started["device_code"])
        let userCode = try #require(started["user_code"])
        #expect(started["verification_uri"] == "https://as.example.com/device")
        #expect(started.json["interval"] as? Int == 5)
        #expect(started.json["expires_in"] as? Int == 600)

        #expect(try await fixture.poll(deviceCode).error == "authorization_pending")
        await fixture.server.requireSlowDown(times: 2)
        #expect(try await fixture.poll(deviceCode).error == "slow_down")
        #expect(try await fixture.poll(deviceCode).error == "slow_down")
        #expect(try await fixture.poll(deviceCode).error == "authorization_pending")

        try await fixture.server.approve(userCode: userCode)
        let granted = try await fixture.poll(deviceCode)
        #expect(granted.status == 200)
        #expect(granted.scope == ["read"])
        #expect(!granted.refreshToken.isEmpty)
        #expect(try await fixture.poll(deviceCode).error == "invalid_grant")
        #expect(await fixture.server.requestCount(for: .deviceCode) == 6)
    }

    @Test("device grant: denial and expiry")
    func deviceDenyAndExpire() async throws {
        let fixture = Fixture()
        let denied = try await fixture.startDevice()
        try await fixture.server.deny(userCode: try #require(denied["user_code"]))
        let denial = try await fixture.poll(try #require(denied["device_code"]))
        #expect(denial.status == 400)
        #expect(denial.error == "access_denied")

        let expiring = try await fixture.startDevice()
        fixture.wallClock.advance(by: .seconds(601))
        #expect(try await fixture.poll(try #require(expiring["device_code"])).error == "expired_token")
        await #expect(throws: FakeAuthorizationServer.ControlError.self) {
            try await fixture.server.approve(userCode: "UNKNOWN")
        }
    }
}
