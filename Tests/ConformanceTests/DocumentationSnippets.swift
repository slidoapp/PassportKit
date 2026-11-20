import Foundation
import HTTPTypes
import Logging
import PassportKit
import PassportKitTesting

// The code samples of README.md and the DocC articles in Sources/PassportKit/PassportKit.docc, kept here so that the compiler
// checks them against the real API. They are never run. When you change a sample in an article, change it here.

enum DocumentationSnippets {
    // GettingStarted.md
    static func gettingStarted() async throws {
        let issuer = URL(string: "https://as.example.com")!
        let metadata = try await Discovery.fetchMetadata(issuer: issuer)
        let configuration = try OAuthClient.Configuration(
            metadata: metadata, authentication: .publicClient(clientID: "my-app"))
        let client = try OAuthClient(configuration: configuration)

        let authorization = try await client.beginDeviceAuthorization(scope: ["openid", "offline_access"])
        print("Open \(authorization.verificationURI) and enter \(authorization.userCode)")
        let tokens = try await client.completeDeviceAuthorization(authorization)

        let account = CredentialAccount(service: "com.example.app", account: "default")
        let session = OAuthSession(client: client, store: .inMemory(), account: account)
        try await session.signIn(with: tokens, requestedScope: ["openid", "offline_access"])

        let token = try await session.accessToken()
        _ = token

        let api = ProtectedResourceClient(session: session, allowedOrigins: [URL(string: "https://api.example.com")!])
        let urlSession = URLSession(configuration: .ephemeral)
        let request = URLRequest(url: URL(string: "https://api.example.com/items")!)
        let (data, response) = try await api.data(for: request, urlSession: urlSession)
        _ = (data, response)
    }

    // GettingStarted.md, local development servers
    static func localDevelopment() async throws -> OAuthClient.Configuration {
        let issuer = URL(string: "http://localhost:8080")!
        let metadata = try await Discovery.fetchMetadata(issuer: issuer, allowsInsecureLoopbackEndpoints: true)
        let configuration = try OAuthClient.Configuration(
            metadata: metadata, authentication: .publicClient(clientID: "my-app"),
            allowsInsecureLoopbackEndpoints: true)
        return configuration
    }

    // README.md, quick start
    static func readmeQuickStart() async throws {
        let issuer = URL(string: "https://as.example.com")!
        let metadata = try await Discovery.fetchMetadata(issuer: issuer)
        let configuration = try OAuthClient.Configuration(
            metadata: metadata, authentication: .publicClient(clientID: "my-app"))
        let client = try OAuthClient(configuration: configuration)

        // 1. Sign in. Show the code, then wait for the person to approve.
        let authorization = try await client.beginDeviceAuthorization(scope: ["openid", "offline_access"])
        print("Open \(authorization.verificationURI) and enter \(authorization.userCode)")
        let tokens = try await client.completeDeviceAuthorization(authorization)

        // 2. Keep the session. It stores, rotates and refreshes the tokens.
        let account = CredentialAccount(service: "com.example.app", account: "default")
        let session = OAuthSession(client: client, store: .inMemory(), account: account)
        try await session.signIn(with: tokens, requestedScope: ["openid", "offline_access"])

        // 3. Call an API. The resource client adds the token and refreshes it once if the server rejects it.
        let api = ProtectedResourceClient(session: session, allowedOrigins: [URL(string: "https://api.example.com")!])
        let request = URLRequest(url: URL(string: "https://api.example.com/items")!)
        let (data, response) = try await api.data(for: request, urlSession: URLSession(configuration: .ephemeral))
        _ = (data, response)
    }

    // GettingStarted.md, logging
    static func logging(configuration: OAuthClient.Configuration) throws -> OAuthClient {
        var logger = Logger(label: "com.example.app.auth")
        logger.logLevel = .debug
        let client = try OAuthClient(configuration: configuration, logger: logger)
        return client
    }

    static func signIn(client: OAuthClient, using userAgent: any AuthorizationUserAgent) async throws -> TokenResponse {
        let request = AuthorizationRequest(
            redirectURI: URL(string: "com.example.app:/callback")!,
            scope: ["openid", "offline_access"])
        return try await client.authorize(request, using: userAgent)
    }

    // SessionsAndTokenTargets.md
    static func targets(session: OAuthSession) async throws {
        let items = URL(string: "https://api.example.com/items")!

        let general = try await session.accessToken()
        let bound = try await session.accessToken(
            for: .refreshGrant(resources: [items], scope: ["items.read"]))
        let exchanged = try await session.accessToken(
            for: .tokenExchange(audiences: ["reports"]))
        _ = (general, bound, exchanged)
    }

    // SessionsAndTokenTargets.md
    static func seededSession(
        session: OAuthSession, reportsClient: OAuthClient, reportsStore: any CredentialStore,
        reportsAccount: CredentialAccount
    ) async throws {
        let reports = OAuthSession(client: reportsClient, store: reportsStore, account: reportsAccount)

        let issued = try await session.exchangeRefreshToken(audiences: ["reports"])
        try await reports.signIn(refreshToken: issued.accessToken, grantedScope: ["reports.read"])

        let token = try await reports.accessToken()
        _ = token
    }

    // MigratingStoredTokens.md
    static func loadLegacyRefreshToken() -> String? { nil }
    static func deleteLegacyItem() {}

    // MigratingStoredTokens.md
    static func migratedSession(client: OAuthClient) async throws -> OAuthSession {
        // A different service than the old item used.
        let account = CredentialAccount(service: "com.example.app.passportkit", account: "default")
        let session = OAuthSession(client: client, store: .keychain(), account: account)
        _ = try await session.restore()

        guard let legacyRefreshToken = loadLegacyRefreshToken() else { return session }
        if await session.credential == nil {
            try await session.signIn(
                refreshToken: Secret(legacyRefreshToken), grantedScope: ["openid", "offline_access"])
        }
        do {
            _ = try await session.accessToken()
            deleteLegacyItem()
        } catch {
            // Keep the old item: a transient failure must not sign the user out. The next launch tries again.
        }
        return session
    }

    // ResourceAccessAndScopes.md
    static func origins(session: OAuthSession) {
        let api = ProtectedResourceClient(
            session: session, allowedOrigins: [URL(string: "https://api.example.com")!])
        _ = api
    }

    // ResourceAccessAndScopes.md
    static func httpTypes(api: ProtectedResourceClient) async throws {
        let request = HTTPRequest(
            method: .post, url: URL(string: "https://api.example.com/items")!,
            headerFields: [.contentType: "application/json"])
        let (response, body) = try await api.send(request, body: Data(#"{"name":"a"}"#.utf8))
        _ = (response, body)
    }

    // ResourceAccessAndScopes.md
    static func policy(client: OAuthClient, account: CredentialAccount) {
        let session = OAuthSession(
            client: client, store: .inMemory(), account: account,
            acceptancePolicy: .requireAnyScope(["items.read", "items.write"]))
        _ = session
    }

    static func prefixPolicy(client: OAuthClient, account: CredentialAccount) {
        let session = OAuthSession(
            client: client, store: .inMemory(), account: account,
            acceptancePolicy: .custom { context in
                guard let granted = context.token.grantedScope else {
                    return .reject(reason: "The granted scope is unknown.")
                }
                return granted.scopes.contains { $0.hasPrefix("items.") }
                    ? .accept : .reject(reason: "No items scope was granted.")
            })
        _ = session
    }

    static func customPolicy(client: OAuthClient, account: CredentialAccount) {
        let session = OAuthSession(
            client: client, store: .inMemory(), account: account,
            acceptancePolicy: .custom { context in
                context.token.grantedScope?.scopes.contains("items.read") == true
                    ? .accept : .reject(reason: "The items scope is missing.")
            })
        _ = session
    }

    static func items(using session: OAuthSession) async throws -> Data? {
        do {
            let token = try await session.accessToken(
                for: .refreshGrant(resources: [URL(string: "https://api.example.com/items")!]))
            // Use the token.
            _ = token
            return nil
        } catch let error as PassportError where error.recovery == .resourceDenied {
            // This person cannot use this resource. Hide the feature; stay signed in.
            return nil
        }
    }

    // ErrorHandling.md
    static func handle(_ error: PassportError) {
        switch error.recovery {
        case .reauthenticate:
            // The root grant is gone. Show the sign-in screen.
            break
        case .resourceDenied:
            // This resource or audience is not available to this person. The session is fine.
            break
        case .retryLater(let after):
            // A transient failure. Retry no sooner than `after` when the server gave one.
            _ = after
        case .fixConfiguration:
            // A bug in the client setup or the request. Retrying cannot help; log it.
            break
        case .noAction:
            // Nothing to recover from, for example the person declined.
            break
        }
    }

    static func watch(_ session: OAuthSession) async {
        for await event in session.events {
            if case .signedOut(let reason) = event {
                print("Signed out: \(reason)")
            }
        }
    }

    // Testing.md
    static func signIn() async throws -> (OAuthClient, FakeAuthorizationServer, TokenResponse) {
        let server = FakeAuthorizationServer(clients: [
            .init(id: "app", rotatesRefreshTokens: true)
        ])
        let client = try await server.makeClient(clientID: "app")
        let request = AuthorizationRequest(
            redirectURI: URL(string: "https://app.example.com/callback")!, scope: ["read"])
        let tokens = try await client.authorize(request, using: server.userAgent())
        return (client, server, tokens)
    }
}
