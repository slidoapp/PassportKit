import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("Fake server: metadata, authorization code and client credentials")
struct AuthorizationGrantTests {
    @Test("metadata advertises the endpoints at the issuer")
    func metadata() async throws {
        let fixture = Fixture()
        let response = try await fixture.get(
            URL(string: "https://as.example.com/.well-known/oauth-authorization-server")!)
        let reply = Reply(response: response)
        #expect(reply.status == 200)
        #expect(reply["issuer"] == "https://as.example.com")
        #expect(reply["token_endpoint"] == "https://as.example.com/token")
        #expect(reply["device_authorization_endpoint"] == "https://as.example.com/device_authorization")
        #expect(reply.json["code_challenge_methods_supported"] as? [String] == ["S256"])
        #expect(reply.json["authorization_response_iss_parameter_supported"] as? Bool == true)

        await fixture.server.configure { $0.advertisedIssuer = "https://other.example.com" }
        let changed = Reply(
            response: try await fixture.get(URL(string: "https://as.example.com/.well-known/openid-configuration")!))
        #expect(changed["issuer"] == "https://other.example.com")
    }

    @Test("authorization code with PKCE yields tokens and a callback with state and iss")
    func codeGrant() async throws {
        let fixture = Fixture()
        let callback = try await fixture.server.authorizeInteractively(fixture.authorizationURL())
        #expect(fixture.callbackValue("state", in: callback) == "st-1")
        #expect(fixture.callbackValue("iss", in: callback) == "https://as.example.com")
        #expect(callback.absoluteString.hasPrefix("https://app.example.com/callback?"))

        let reply = try await fixture.signIn()
        #expect(reply.status == 200)
        #expect(reply["token_type"] == "Bearer")
        #expect(reply.scope == ["read", "write"])
        #expect(reply.json["expires_in"] as? Int == 900)
        #expect(!reply.refreshToken.isEmpty)
        #expect(try await fixture.api(reply.accessToken).statusCode == 200)
    }

    @Test("a replayed code fails and revokes what it issued")
    func codeReplay() async throws {
        let fixture = Fixture()
        let callback = try await fixture.server.authorizeInteractively(fixture.authorizationURL())
        let form = [
            ("grant_type", "authorization_code"), ("code", fixture.callbackValue("code", in: callback) ?? ""),
            ("redirect_uri", "https://app.example.com/callback"), ("code_verifier", pkceVerifier),
        ]
        let first = try await fixture.token(form)
        let second = try await fixture.token(form)
        #expect(second.status == 400)
        #expect(second.error == "invalid_grant")
        #expect(try await fixture.api(first.accessToken).statusCode == 401)
        #expect(try await fixture.refresh(first.refreshToken).error == "invalid_grant")
    }

    @Test("PKCE verification", arguments: [("wrong", "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXl"), ("missing", "")])
    func pkceMismatch(_ label: String, _ verifier: String) async throws {
        let fixture = Fixture()
        let callback = try await fixture.server.authorizeInteractively(fixture.authorizationURL())
        let form = [
            ("grant_type", "authorization_code"), ("code", fixture.callbackValue("code", in: callback) ?? ""),
            ("redirect_uri", "https://app.example.com/callback"),
        ]
        let reply = try await fixture.token(verifier.isEmpty ? form : form + [("code_verifier", verifier)])
        #expect(reply.status == 400, Comment(rawValue: label))
        #expect(reply.error == "invalid_grant")
    }

    @Test("a redirect URI that differs from the authorization request is rejected")
    func redirectMismatch() async throws {
        let fixture = Fixture()
        let callback = try await fixture.server.authorizeInteractively(fixture.authorizationURL())
        let reply = try await fixture.token([
            ("grant_type", "authorization_code"), ("code", fixture.callbackValue("code", in: callback) ?? ""),
            ("redirect_uri", "https://app.example.com/other"), ("code_verifier", pkceVerifier),
        ])
        #expect(reply.error == "invalid_grant")
    }

    @Test("authorization request problems come back as error callbacks")
    func authorizationErrors() async throws {
        let fixture = Fixture()
        let noChallenge = try await fixture.server.authorizeInteractively(fixture.authorizationURL(challenge: nil))
        #expect(fixture.callbackValue("error", in: noChallenge) == "invalid_request")
        let badScope = try await fixture.server.authorizeInteractively(fixture.authorizationURL(scope: "read nuke"))
        #expect(fixture.callbackValue("error", in: badScope) == "invalid_scope")
        let denied = try await fixture.server.authorizeInteractively(fixture.authorizationURL(), decision: .deny)
        #expect(fixture.callbackValue("error", in: denied) == "access_denied")
        #expect(fixture.callbackValue("state", in: denied) == "st-1")
        await #expect(throws: FakeAuthorizationServer.ControlError.self) {
            try await fixture.server.authorizeInteractively(
                fixture.authorizationURL(redirect: "https://evil.example.com/cb"))
        }
    }

    @Test("the iss parameter can be omitted or forged")
    func issuerParameter() async throws {
        let fixture = Fixture()
        await fixture.server.configure { $0.issuerParameter = .omitted }
        let omitted = try await fixture.server.authorizeInteractively(fixture.authorizationURL())
        #expect(fixture.callbackValue("iss", in: omitted) == nil)
        await fixture.server.configure { $0.issuerParameter = .value("https://evil.example.com") }
        let forged = try await fixture.server.authorizeInteractively(fixture.authorizationURL())
        #expect(fixture.callbackValue("iss", in: forged) == "https://evil.example.com")
    }

    @Test("loopback redirects match with any port")
    func loopbackRedirect() async throws {
        let client = FakeAuthorizationServer.ClientRegistration(id: "app", redirectURIs: ["http://127.0.0.1/callback"])
        let fixture = Fixture([client])
        let callback = try await fixture.server.authorizeInteractively(
            fixture.authorizationURL(redirect: "http://127.0.0.1:53124/callback"))
        #expect(callback.port == 53124)
        #expect(fixture.callbackValue("code", in: callback) != nil)
    }

    @Test("client credentials works with basic and post authentication and issues no refresh token")
    func clientCredentials() async throws {
        let fixture = Fixture()
        let form = [("grant_type", "client_credentials"), ("scope", "read")]
        for auth in [Authentication.basic("service", "s3cret"), .post("service", "s3cret")] {
            let reply = try await fixture.token(form, as: auth)
            #expect(reply.status == 200)
            #expect(reply.scope == ["read"])
            #expect(reply["refresh_token"] == nil)
        }
        #expect(await fixture.server.requestCount(for: .clientCredentials) == 2)
        #expect(
            try await fixture.token(
                [("grant_type", "client_credentials"), ("scope", "admin")], as: .basic("service", "s3cret")
            ).error == "invalid_scope")
    }

    @Test("client authentication failures are 401 invalid_client with an RFC 6749 body")
    func clientAuthentication() async throws {
        let fixture = Fixture()
        let form = [("grant_type", "client_credentials")]
        let unknown = try await fixture.token(form, as: .basic("nobody", "x"))
        #expect(unknown.status == 401)
        #expect(unknown.error == "invalid_client")
        #expect(unknown.response.headers["WWW-Authenticate"]?.hasPrefix("Basic") == true)
        #expect(try await fixture.token(form, as: .post("service", "wrong")).status == 401)
        #expect(try await fixture.token(form, as: .publicClient("service")).error == "invalid_client")
    }

    @Test("grant type errors")
    func grantTypeErrors() async throws {
        let fixture = Fixture()
        #expect(try await fixture.token([("grant_type", "password")]).error == "unsupported_grant_type")
        #expect(try await fixture.token([]).error == "invalid_request")
        let notAllowed = try await fixture.token(
            [("grant_type", "client_credentials")], as: .basic("service", "s3cret"))
        #expect(notAllowed.status == 200)
        #expect(try await fixture.token([("grant_type", "client_credentials")]).error == "unauthorized_client")
    }

    @Test("the scope policy narrows grants without an error")
    func scopePolicy() async throws {
        let fixture = Fixture()
        await fixture.server.configure { $0.scopePolicy = { _, _ in ["read"] } }
        let reply = try await fixture.signIn(scope: "read write")
        #expect(reply.status == 200)
        #expect(reply.scope == ["read"])
    }
}
