import Foundation
import PassportKit
import Testing

@Suite(
    "Token manager against the server",
    .enabled(if: IntegrationServer.isConfigured, "Set PASSPORTKIT_INTEGRATION_ISSUER or run `make integration`."),
    .timeLimit(.minutes(1))
)
struct SessionTests {
    @Test func refreshRotatesTheTokenAndRejectsReuse() async throws {
        // A minimum lifetime above the server's token lifetime makes every cached token stale.
        let session = try await IntegrationServer.signIn(minimumTokenLifetime: .seconds(3600))
        let original = try #require(await session.refreshToken)

        let token = try await session.manager.accessToken()
        #expect(token.grantedScope?.contains("api:read") == true)

        let rotated = try #require(await session.refreshToken)
        #expect(rotated != original)
        #expect(try await session.store.load(session.account)?.refreshToken == rotated)

        let reuse = await passportError { _ = try await session.client.refresh(original) }
        #expect(reuse?.code == .invalidGrant)
        #expect(reuse?.recovery == .reauthenticate)
    }

    @Test func exchangedAccessTokenForAnAllowedResourceSucceeds() async throws {
        let session = try await IntegrationServer.signIn()
        let target = TokenTarget.exchange(resources: [IntegrationServer.allowedResource])
        let token = try await session.manager.accessToken(for: target)
        #expect(token.grantedScope?.contains("api:read") == true)
        #expect(token.target == target)
    }

    @Test func exchangeForADeniedResourceFailsAndKeepsTheSession() async throws {
        let session = try await IntegrationServer.signIn()
        let target = TokenTarget.exchange(resources: [IntegrationServer.deniedResource])

        let error = await passportError { _ = try await session.manager.accessToken(for: target) }
        #expect(error?.code == .accessDenied)
        #expect(error?.recovery == .resourceDenied)

        #expect(await session.manager.credential != nil)
        _ = try await session.manager.accessToken()
        let allowed = TokenTarget.exchange(resources: [IntegrationServer.allowedResource])
        _ = try await session.manager.accessToken(for: allowed)
    }

    @Test func underscopedRefreshGrantIsRejectedButRotationIsKept() async throws {
        let session = try await IntegrationServer.signIn(policy: RequireAnyScope(["api:read", "api:write"]))
        let original = try #require(await session.refreshToken)

        // Control: the same kind of target for an allowed resource is accepted.
        let allowed = TokenTarget.refreshGrant(resources: [IntegrationServer.allowedResource])
        _ = try await session.manager.accessToken(for: allowed)

        let denied = TokenTarget.refreshGrant(resources: [IntegrationServer.deniedResource])
        let error = await passportError { _ = try await session.manager.accessToken(for: denied) }
        #expect(error?.code == .tokenRejected)
        #expect(error?.recovery == .resourceDenied)

        // The rotated token from the rejected 200 was kept, and the session still works.
        let current = try #require(await session.refreshToken)
        #expect(current != original)
        #expect(try await session.store.load(session.account)?.refreshToken == current)
        _ = try await session.manager.accessToken(for: allowed)
    }

    @Test func refreshTokenExchangeForAnAudienceRotatesTheSubject() async throws {
        let session = try await IntegrationServer.signIn()
        let original = try #require(await session.refreshToken)

        let response = try await session.manager.exchangeRefreshToken(audiences: [IntegrationServer.audienceClientID])
        #expect(response.issuedTokenType == .refreshToken)
        #expect(response.accessToken != original)

        let rotated = try #require(await session.refreshToken)
        #expect(rotated != original)
        #expect(try await session.store.load(session.account)?.refreshToken == rotated)

        // The audience's refresh token is usable by the audience client.
        let audienceClient = try await IntegrationServer.client(
            authentication: .publicClient(clientID: IntegrationServer.audienceClientID))
        let audienceTokens = try await audienceClient.refresh(response.accessToken)
        #expect(audienceTokens.refreshToken != nil)

        // The rotated subject keeps working: a refresh with a resource sends it.
        let target = TokenTarget.refreshGrant(resources: [IntegrationServer.allowedResource])
        _ = try await session.manager.accessToken(for: target)
    }

    @Test func signOutRevokesTheRefreshToken() async throws {
        let session = try await IntegrationServer.signIn()
        let refreshToken = try #require(await session.refreshToken)

        let result = await session.manager.signOut(revoke: true)
        #expect(result.revocation == .revoked)
        #expect(result.isStoredCredentialDeleted)
        #expect(await session.manager.credential == nil)

        let error = await passportError { _ = try await session.client.refresh(refreshToken) }
        #expect(error?.code == .invalidGrant)
    }
}

@Suite(
    "Client credentials against the server",
    .enabled(if: IntegrationServer.isConfigured, "Set PASSPORTKIT_INTEGRATION_ISSUER or run `make integration`."),
    .timeLimit(.minutes(1))
)
struct ClientCredentialsTests {
    @Test(
        arguments: [
            ClientAuthentication.clientSecretBasic(
                clientID: IntegrationServer.serviceClientID, secret: IntegrationServer.serviceSecret),
            ClientAuthentication.clientSecretPost(
                clientID: IntegrationServer.serviceClientID, secret: IntegrationServer.serviceSecret),
        ]
    )
    func clientCredentialsGrantIssuesAnAccessToken(authentication: ClientAuthentication) async throws {
        let client = try await IntegrationServer.client(authentication: authentication)
        let response = try await client.clientCredentials(resources: [IntegrationServer.allowedResource])
        #expect(response.tokenType.lowercased() == "bearer")
        #expect(response.refreshToken == nil)
    }

    @Test func wrongSecretIsRejectedAsInvalidClient() async throws {
        let client = try await IntegrationServer.client(
            authentication: .clientSecretBasic(clientID: IntegrationServer.serviceClientID, secret: Secret("wrong")))
        let error = await passportError {
            _ = try await client.clientCredentials(resources: [IntegrationServer.allowedResource])
        }
        #expect(error?.code == .invalidClient)
    }
}
