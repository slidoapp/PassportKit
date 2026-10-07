import Foundation
import PassportKitTesting
import Testing

@testable import PassportKit

@Suite(.timeLimit(.minutes(1)))
struct AuthorizationRequestTests {
    private func client(authorization: URL? = ClientFixtures.authorizationURL) throws -> OAuthClient {
        try ClientFixtures.client(RecordingTransport(), authorization: authorization, random: CountingRandomSource())
    }

    private func pairs(_ url: URL) -> [String] { AuthorizationFixtures.query(of: url).map { "\($0.0)=\($0.1)" } }

    @Test func urlCarriesEveryParameterInOrder() throws {
        let pending = try client().beginAuthorization(
            AuthorizationRequest(
                redirectURI: AuthorizationFixtures.redirectURI,
                scope: ["b", "a"],
                resources: [URL(string: "https://api.example.com/v1")!, URL(string: "https://other.example.com")!],
                loginHint: "ann@example.com",
                prompt: [.consent],
                additionalParameters: ["audience_hint": "x y"]
            ))
        let verifier = Secret(CountingRandomSource.text(call: 2))
        #expect(pending.url.absoluteString.hasPrefix("https://as.example.com/oauth/authorize?response_type=code&"))
        #expect(
            pairs(pending.url) == [
                "response_type=code", "client_id=app", "redirect_uri=https://app.example.com/callback",
                "state=\(CountingRandomSource.text(call: 1))",
                "code_challenge=\(PKCE.challenge(for: verifier))", "code_challenge_method=S256",
                "scope=a b", "resource=https://api.example.com/v1", "resource=https://other.example.com",
                "login_hint=ann@example.com", "prompt=consent", "audience_hint=x y",
            ])
        #expect(pending.redirectURI == AuthorizationFixtures.redirectURI)
    }

    @Test func promptValuesAreOneSpaceDelimitedParameterInGivenOrder() throws {
        let both = try client().beginAuthorization(
            AuthorizationRequest(
                redirectURI: AuthorizationFixtures.redirectURI, prompt: [.login, .selectAccount]))
        #expect(pairs(both.url).contains("prompt=login select_account"))
        let none = try client().beginAuthorization(
            AuthorizationRequest(redirectURI: AuthorizationFixtures.redirectURI))
        #expect(!pairs(none.url).contains { $0.hasPrefix("prompt=") })
        #expect(AuthorizationRequest.Prompt.noInteraction.rawValue == "none")
    }

    @Test func stateAndVerifierAre32RandomBytesEach() throws {
        let pending = try client().beginAuthorization(
            AuthorizationRequest(redirectURI: AuthorizationFixtures.redirectURI))
        #expect(pending.state.reveal() == CountingRandomSource.text(call: 1))
        #expect(pending.codeVerifier.reveal() == CountingRandomSource.text(call: 2))
        #expect(pending.state.reveal().count == 43)
        #expect(pending.state != pending.codeVerifier)
    }

    @Test func existingEndpointQueryIsPreserved() throws {
        let endpoint = URL(string: "https://as.example.com/authorize?tenant=a%20b&ui=1")!
        let pending = try client(authorization: endpoint).beginAuthorization(
            AuthorizationRequest(redirectURI: AuthorizationFixtures.redirectURI))
        let items = pairs(pending.url)
        #expect(Array(items.prefix(2)) == ["tenant=a b", "ui=1"])
        #expect(items[2] == "response_type=code")
    }

    @Test func endpointQueryCollidingWithAParameterIsRejected() throws {
        let endpoint = URL(string: "https://as.example.com/authorize?state=fixed")!
        #expect(throws: PassportError.self) {
            try client(authorization: endpoint).beginAuthorization(
                AuthorizationRequest(redirectURI: AuthorizationFixtures.redirectURI))
        }
    }

    @Test func missingAuthorizationEndpointIsAConfigurationError() throws {
        let error = try #require(
            throws: PassportError.self
        ) {
            try client(authorization: nil).beginAuthorization(
                AuthorizationRequest(redirectURI: AuthorizationFixtures.redirectURI))
        }
        #expect(error.code == .invalidConfiguration)
    }

    @Test func additionalParameterCollisionIsRejected() throws {
        let error = try #require(
            throws: PassportError.self
        ) {
            try client().beginAuthorization(
                AuthorizationRequest(
                    redirectURI: AuthorizationFixtures.redirectURI, additionalParameters: ["code_challenge": "x"]))
        }
        #expect(error.code == .invalidConfiguration)
    }

    @Test(
        arguments: [
            "http://app.example.com/callback", "https://app.example.com/callback#frag", "/callback", "callback",
            "https:///callback",
        ])
    func unsafeRedirectURIsAreRejected(_ redirect: String) throws {
        let error = try #require(
            throws: PassportError.self
        ) {
            try client().beginAuthorization(AuthorizationRequest(redirectURI: URL(string: redirect)!))
        }
        #expect(error.code == .invalidConfiguration)
    }

    @Test(arguments: [
        "http://127.0.0.1:51234/cb", "http://localhost:8080/cb", "http://[::1]:9000/cb", "com.example.app:/cb",
    ])
    func nativeRedirectURIsAreAccepted(_ redirect: String) throws {
        let pending = try client().beginAuthorization(AuthorizationRequest(redirectURI: URL(string: redirect)!))
        #expect(pairs(pending.url).contains("redirect_uri=\(redirect)"))
    }

    @Test func invalidResourceIsRejected() throws {
        #expect(throws: PassportError.self) {
            try client().beginAuthorization(
                AuthorizationRequest(
                    redirectURI: AuthorizationFixtures.redirectURI,
                    resources: [URL(string: "https://api.example.com/#x")!]))
        }
    }

    @Test func descriptionRevealsNeitherStateNorVerifierNorURL() throws {
        let pending = try client().beginAuthorization(
            AuthorizationRequest(redirectURI: AuthorizationFixtures.redirectURI))
        let secrets = [
            CountingRandomSource.text(call: 1), CountingRandomSource.text(call: 2),
            PKCE.challenge(for: pending.codeVerifier),
        ]
        for rendering in Canary.renderings(of: pending) {
            #expect(rendering.contains("PendingAuthorization"))
            #expect(!rendering.contains("authorize"))
            for secret in secrets { #expect(!rendering.contains(secret)) }
        }
    }

    @Test func requiringAnIssuerNeedsOneConfigured() {
        let configuration = ClientFixtures.configuration(requiresIssuer: true)
        #expect(throws: PassportError.self) { try OAuthClient(configuration: configuration) }
    }
}
