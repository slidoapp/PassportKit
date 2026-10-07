import Foundation
import PassportKit
import Testing

@Suite(
    "Discovery and authorization code flow",
    .enabled(if: IntegrationServer.isConfigured, "Set PASSPORTKIT_INTEGRATION_ISSUER or run `make integration`."),
    .timeLimit(.minutes(1))
)
struct AuthorizationTests {
    @Test func discoversMetadataAtTheRFC8414PathAndBuildsAConfiguration() async throws {
        let issuer = try IntegrationServer.requireIssuer()
        let metadata = try await Discovery.fetchMetadata(issuer: issuer, style: .oauth, validation: .strict)
        #expect(metadata.issuer == issuer)
        #expect(metadata.authorizationResponseIssParameterSupported == true)

        let configuration = try ClientConfiguration(
            metadata: metadata, authentication: .none(clientID: IntegrationServer.publicClientID))
        #expect(configuration.issuer == issuer)
        #expect(configuration.requiresIssuerInAuthorizationResponse)
        #expect(configuration.endpoints.deviceAuthorization != nil)
        #expect(configuration.endpoints.revocation != nil)
    }

    @Test func authorizationCodeWithPKCEReturnsGrantedScopeAndRefreshToken() async throws {
        let session = try await IntegrationServer.signIn()
        #expect(session.response.refreshToken != nil)
        let granted = try #require(session.response.scope)
        #expect(IntegrationServer.fullScope.isSubset(of: granted))
        #expect(await session.manager.credential?.grantedScope == granted)
    }

    @Test func callbackCarriesTheIssuerAndTheClientChecksIt() async throws {
        let client = try await IntegrationServer.client()
        let request = AuthorizationRequest(
            redirectURI: IntegrationServer.redirectURI, scope: IntegrationServer.fullScope, prompt: "consent")
        let pending = try client.beginAuthorization(request)
        let callback = try await RedirectFollowingUserAgent().present(
            pending.url, redirectURI: IntegrationServer.redirectURI)
        let issuer = try IntegrationServer.requireIssuer()
        let components = try #require(URLComponents(url: callback, resolvingAgainstBaseURL: false))
        #expect(components.queryItems?.first { $0.name == "iss" }?.value == issuer.absoluteString)
        #expect(client.configuration.requiresIssuerInAuthorizationResponse)
        _ = try await client.completeAuthorization(pending, callbackURL: callback)
    }

    @Test func callbackWithoutIssuerIsRejected() async throws {
        let error = try await rejectedCallback { components in
            components.queryItems?.removeAll { $0.name == "iss" }
        }
        #expect(error?.code == .issuerMismatch)
    }

    @Test func callbackWithAnotherIssuerIsRejected() async throws {
        let error = try await rejectedCallback { components in
            components.queryItems = components.queryItems?.map {
                $0.name == "iss" ? URLQueryItem(name: "iss", value: "https://as.example.com") : $0
            }
        }
        #expect(error?.code == .issuerMismatch)
    }

    private func rejectedCallback(_ tamper: (inout URLComponents) -> Void) async throws -> PassportError? {
        let client = try await IntegrationServer.client()
        let request = AuthorizationRequest(
            redirectURI: IntegrationServer.redirectURI, scope: IntegrationServer.fullScope, prompt: "consent")
        let pending = try client.beginAuthorization(request)
        let callback = try await RedirectFollowingUserAgent().present(
            pending.url, redirectURI: IntegrationServer.redirectURI)
        var components = try #require(URLComponents(url: callback, resolvingAgainstBaseURL: false))
        tamper(&components)
        let tampered = try #require(components.url)
        return await passportError { _ = try await client.completeAuthorization(pending, callbackURL: tampered) }
    }
}
