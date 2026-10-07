#if canImport(Security)
    import Foundation
    import PassportKit
    import PassportKitApple
    import Testing

    @Suite(
        "Keychain store against the server",
        .enabled(if: IntegrationServer.isConfigured, "Set PASSPORTKIT_INTEGRATION_ISSUER or run `make integration`."),
        .timeLimit(.minutes(1))
    )
    struct KeychainTests {
        @Test func rotatedRefreshTokenSurvivesInTheKeychain() async throws {
            let store = KeychainCredentialStore()
            let session = try await IntegrationServer.signIn(store: store, minimumTokenLifetime: .seconds(3600))
            let account = session.account
            let outcome = await Result {
                _ = try await session.manager.accessToken()  // rotates and persists
                let rotated = try #require(await session.refreshToken)
                #expect(try await store.load(account)?.refreshToken == rotated)

                // A new manager restores the session from the Keychain alone and can refresh with it.
                let restored = TokenManager(client: session.client, store: store, account: account)
                #expect(try await restored.load()?.refreshToken == rotated)
                _ = try await restored.accessToken()
                #expect(await restored.credential?.refreshToken != rotated)
            }
            try? await store.delete(account)
            try outcome.get()
            #expect(try await store.load(account) == nil)
        }
    }

    extension Result where Failure == any Error {
        fileprivate init(_ body: () async throws -> Success) async {
            do { self = .success(try await body()) } catch { self = .failure(error) }
        }
    }
#endif
