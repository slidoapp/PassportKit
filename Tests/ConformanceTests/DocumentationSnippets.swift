import Foundation
import PassportKit
import PassportKitTesting

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

// The code samples of the DocC articles in Sources/PassportKit/PassportKit.docc, kept here so that the compiler
// checks them against the real API. They are never run. When you change a sample in an article, change it here.

enum DocumentationSnippets {
    // GettingStarted.md
    static func gettingStarted() async throws {
        let issuer = URL(string: "https://as.example.com")!
        let metadata = try await Discovery.fetchMetadata(issuer: issuer)
        let configuration = try ClientConfiguration(
            metadata: metadata, authentication: .none(clientID: "my-app"))
        let client = try OAuthClient(configuration: configuration)

        let authorization = try await client.startDeviceAuthorization(scope: ["openid", "offline_access"])
        print("Open \(authorization.verificationURI) and enter \(authorization.userCode)")
        let tokens = try await client.completeDeviceAuthorization(authorization)

        let account = CredentialAccount(service: "com.example.app", account: "default")
        let manager = TokenManager(client: client, store: InMemoryCredentialStore(), account: account)
        try await manager.signIn(with: tokens, requestedScope: ["openid", "offline_access"])

        let token = try await manager.accessToken()
        _ = token

        let authorizer = RequestAuthorizer(manager: manager)
        let session = URLSession(configuration: .ephemeral)
        let request = URLRequest(url: URL(string: "https://api.example.com/items")!)
        let (data, response) = try await authorizer.data(for: request, session: session)
        _ = (data, response)
    }

    static func signIn(client: OAuthClient, using userAgent: any UserAgent) async throws -> TokenResponse {
        let request = AuthorizationRequest(
            redirectURI: URL(string: "com.example.app:/callback")!,
            scope: ["openid", "offline_access"])
        return try await client.authorize(request, using: userAgent)
    }

    // SessionsAndTokenTargets.md
    static func targets(manager: TokenManager) async throws {
        let items = URL(string: "https://api.example.com/items")!

        let general = try await manager.accessToken()
        let bound = try await manager.accessToken(
            for: TokenTarget(resources: [items], scope: ["items.read"]))
        let exchanged = try await manager.accessToken(
            for: TokenTarget(method: .exchangeAccessToken, audiences: ["reports"]))
        _ = (general, bound, exchanged)
    }

    // ResourceAccessAndScopes.md
    static func policy(client: OAuthClient, account: CredentialAccount) {
        let policy = RequireAnyScope(["items.read", "items.write"])
        let manager = TokenManager(
            client: client, store: InMemoryCredentialStore(), account: account, acceptancePolicy: policy)
        _ = manager
    }

    static func items(using manager: TokenManager) async throws -> Data? {
        do {
            let token = try await manager.accessToken(
                for: TokenTarget(resources: [URL(string: "https://api.example.com/items")!]))
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
        case .none:
            // Nothing to recover from, for example the person declined.
            break
        }
    }

    static func watch(_ manager: TokenManager) async {
        for await event in manager.events {
            if case .signedOut(let reason) = event {
                print("Signed out: \(reason)")
            }
        }
    }

    // Testing.md
    static func makeClient() throws -> (OAuthClient, FakeAuthorizationServer) {
        let server = FakeAuthorizationServer(clients: [
            .init(id: "app", rotatesRefreshTokens: true)
        ])
        let configuration = ClientConfiguration(
            endpoints: Endpoints(
                authorization: FakeAuthorizationServer.authorizationEndpoint,
                token: FakeAuthorizationServer.tokenEndpoint),
            authentication: .none(clientID: "app"),
            issuer: FakeAuthorizationServer.issuer)
        let client = try OAuthClient(configuration: configuration, transport: server)
        return (client, server)
    }

    struct ApprovingUserAgent: UserAgent {
        let server: FakeAuthorizationServer

        func present(_ url: URL, redirectURI: URL) async throws -> URL {
            try await server.authorizeInteractively(url)
        }
    }
}
