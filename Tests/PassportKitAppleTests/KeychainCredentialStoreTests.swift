#if canImport(Security)
    import Foundation
    import PassportKit
    import PassportKitTesting
    import Security
    import Testing

    @testable import PassportKitApple

    /// Uses the real Keychain of the test host with a unique service per test, removed on exit. The default
    /// store uses the login keychain on macOS, which `swift test` can reach without entitlements; the data
    /// protection keychain needs a signed host, so its test runs only when the host grants access.
    @Suite("Keychain credential store", .timeLimit(.minutes(1)))
    struct KeychainCredentialStoreTests {
        private let account = CredentialAccount(service: "PassportKitTests.\(UUID())", account: "user")

        private func credential(_ token: String = "refresh-1", updatedAt: TimeInterval = 1_700_000_000) -> Credential {
            Credential(
                clientID: "app", issuer: URL(string: "https://as.example.com"), refreshToken: Secret(token),
                grantedScope: ["read"], updatedAt: Date(timeIntervalSince1970: updatedAt),
                additionalFields: ["tenant": .string("t1")])
        }

        private func itemCount() -> Int {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: account.service,
                kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitAll,
            ]
            var result: CFTypeRef?
            guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess else { return 0 }
            return (result as? [[String: Any]])?.count ?? 0
        }

        private func rawWrite(_ data: Data) {
            let status = SecItemAdd(
                [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: account.service,
                    kSecAttrAccount as String: account.account,
                    kSecValueData as String: data,
                ] as CFDictionary, nil)
            #expect(status == errSecSuccess)
        }

        @Test func roundTrip() async throws {
            let store = KeychainCredentialStore()
            defer { cleanUp() }
            #expect(try await store.load(account) == nil)
            try await store.save(credential(), for: account)
            #expect(try await store.load(account) == credential())
        }

        @Test func updatesInPlace() async throws {
            let store = KeychainCredentialStore()
            defer { cleanUp() }
            try await store.save(credential("refresh-1"), for: account)
            try await store.save(credential("refresh-2"), for: account)
            #expect(try await store.load(account)?.refreshToken?.reveal() == "refresh-2")
            #expect(itemCount() == 1)
        }

        @Test func deleteIsIdempotent() async throws {
            let store = KeychainCredentialStore()
            defer { cleanUp() }
            try await store.delete(account)
            try await store.save(credential(), for: account)
            try await store.delete(account)
            try await store.delete(account)
            #expect(try await store.load(account) == nil)
            #expect(itemCount() == 0)
        }

        @Test func corruptPayloadIsAStorageFailureWithoutLeakingIt() async throws {
            defer { cleanUp() }
            rawWrite(Data("secret-looking-garbage".utf8))
            let error = try await #require(throws: PassportError.self) {
                try await KeychainCredentialStore().load(account)
            }
            #expect(error.code == .storageFailure)
            #expect(!error.description.contains("garbage"))
        }

        @Test func legacyPayloadIsDecodedAndRewrittenInTheCurrentFormat() async throws {
            defer { cleanUp() }
            rawWrite(Data("legacy:refresh-9".utf8))
            let migrated = credential("refresh-9")
            let store = KeychainCredentialStore(decodeLegacy: { data in
                let text = String(decoding: data, as: UTF8.self)
                return text.hasPrefix("legacy:") ? migrated : nil
            })
            #expect(try await store.load(account) == migrated)
            // The next load needs no hook: the payload is a current record now.
            #expect(try await KeychainCredentialStore().load(account) == migrated)
            #expect(itemCount() == 1)
        }

        @Test func legacyHookDoesNotRunForCurrentRecords() async throws {
            let store = KeychainCredentialStore(decodeLegacy: { _ in
                Issue.record("The hook must only see payloads the current format rejects.")
                return nil
            })
            defer { cleanUp() }
            try await store.save(credential(), for: account)
            #expect(try await store.load(account) == credential())
        }

        @Test func concurrentSavesDoNotFail() async throws {
            let store = KeychainCredentialStore()
            defer { cleanUp() }
            try await withThrowingTaskGroup(of: Void.self) { group in
                for index in 0..<16 {
                    group.addTask { try await store.save(credential("refresh-\(index)"), for: account) }
                }
                try await group.waitForAll()
            }
            #expect(try await store.load(account) != nil)
            #expect(itemCount() == 1)
        }

        @Test func separateStoresRacingToCreateTheItemDoNotFail() async throws {
            defer { cleanUp() }
            try await withThrowingTaskGroup(of: Void.self) { group in
                for index in 0..<8 {
                    group.addTask {
                        try await KeychainCredentialStore().save(credential("refresh-\(index)"), for: account)
                    }
                }
                try await group.waitForAll()
            }
            #expect(itemCount() == 1)
        }

        @Test func storedItemIsNotSynchronizable() async throws {
            let store = KeychainCredentialStore()
            defer { cleanUp() }
            try await store.save(credential(), for: account)
            let attributes = try storedAttributes()
            // The attribute reads back as false (0) or is absent; it is never true.
            let synchronizable = attributes[kSecAttrSynchronizable as String] as? Bool
            #expect(synchronizable != true)
            #if !os(macOS)
                // The file-based keychain of macOS has no accessibility classes; the setting is applied there only
                // with the data protection keychain, which an unsigned test host cannot use.
                let accessible = attributes[kSecAttrAccessible as String] as? String
                #expect(accessible == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as String)
            #endif
        }

        @Test func lockedDeviceIsRetryableAndOtherStatusesAreNot() {
            let locked = KeychainCredentialStore.failure(errSecInteractionNotAllowed)
            #expect(locked.code == .storageFailure)
            #expect(locked.recovery == .retryLater(after: nil))
            let other = KeychainCredentialStore.failure(errSecAuthFailed)
            #expect(other.code == .storageFailure)
            #expect(other.recovery != .retryLater(after: nil))
            #expect(other.description.contains("\(errSecAuthFailed)"))
        }

        private func storedAttributes() throws -> [String: Any] {
            let query: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrService as String: account.service,
                kSecAttrAccount as String: account.account,
                kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
                kSecReturnAttributes as String: true,
                kSecMatchLimit as String: kSecMatchLimitOne,
            ]
            var result: CFTypeRef?
            try #require(SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess)
            return try #require(result as? [String: Any])
        }

        #if os(macOS)
            @Test func dataProtectionKeychainWhenTheHostAllowsIt() async throws {
                let store = KeychainCredentialStore(useDataProtectionKeychain: true)
                defer { try? deleteDataProtectionItem() }
                do {
                    try await store.save(credential(), for: account)
                } catch let error as PassportError {
                    // errSecMissingEntitlement: an unsigned `swift test` host has no keychain access group.
                    #expect(error.code == .storageFailure)
                    #expect(error.description.contains("-34018"))
                    return
                }
                #expect(try await store.load(account) == credential())
                try await store.delete(account)
                #expect(try await store.load(account) == nil)
            }

            private func deleteDataProtectionItem() throws {
                SecItemDelete(
                    [
                        kSecClass as String: kSecClassGenericPassword,
                        kSecAttrService as String: account.service,
                        kSecUseDataProtectionKeychain as String: true,
                    ] as CFDictionary)
            }
        #endif

        @Test func tokenManagerRotationSurvivesARestart() async throws {
            defer { cleanUp() }
            let registration = FakeAuthorizationServer.ClientRegistration(
                id: "app", allowedGrants: [.authorizationCode, .refreshToken], scope: ["read"],
                rotatesRefreshTokens: true, revokesGrantOnReuse: true, accessTokenLifetime: .seconds(900))
            let wallClock = ManualWallClock()
            let server = FakeAuthorizationServer(
                clients: [registration], wallClock: wallClock, clock: ManualClock())
            let client = try OAuthClient(
                configuration: ClientConfiguration(
                    endpoints: Endpoints(
                        authorization: FakeAuthorizationServer.authorizationEndpoint,
                        token: FakeAuthorizationServer.tokenEndpoint,
                        revocation: FakeAuthorizationServer.revocationEndpoint),
                    authentication: .publicClient(clientID: "app"), issuer: FakeAuthorizationServer.issuer),
                transport: server, wallClock: wallClock, clock: ManualClock(), random: SequenceRandomSource())
            let store = KeychainCredentialStore()

            let manager = TokenManager(client: client, store: store, account: account)
            let response = try await client.authorize(
                AuthorizationRequest(
                    redirectURI: try #require(URL(string: "https://app.example.com/callback")), scope: ["read"]),
                using: server.userAgent())
            try await manager.signIn(with: response, requestedScope: ["read"])
            let first = try await #require(store.load(account)?.refreshToken?.reveal())

            wallClock.advance(by: .seconds(1000))
            _ = try await manager.accessToken()
            let rotated = try await #require(store.load(account)?.refreshToken?.reveal())
            #expect(rotated != first)

            let restarted = TokenManager(client: client, store: store, account: account)
            let restored = try await restarted.load()
            #expect(restored?.refreshToken?.reveal() == rotated)
            wallClock.advance(by: .seconds(1000))
            _ = try await restarted.accessToken()
        }

        private func cleanUp() {
            SecItemDelete(
                [
                    kSecClass as String: kSecClassGenericPassword,
                    kSecAttrService as String: account.service,
                    kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
                ] as CFDictionary)
        }
    }
#endif
