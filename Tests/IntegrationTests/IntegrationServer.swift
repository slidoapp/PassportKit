import Foundation
import PassportKit
import Testing

/// The local `oidc-provider` server in `Tools/integration-server`, started by `make integration`.
///
/// Every test builds its own client and session; nothing is shared between tests.
enum IntegrationServer {
    static let issuerVariable = "PASSPORTKIT_INTEGRATION_ISSUER"

    static let issuer: URL? = ProcessInfo.processInfo.environment[issuerVariable].flatMap { URL(string: $0) }

    static let isConfigured = issuer != nil

    static let publicClientID = "public-native"
    static let audienceClientID = "audience-client"
    static let serviceClientID = "confidential-service"
    static let serviceSecret = Secret("integration-secret")

    static let fullScope: ScopeSet = ["openid", "offline_access", "api:read", "api:write"]
    static let allowedResource = URL(string: "https://api.example.com/allowed/1")!
    static let deniedResource = URL(string: "https://api.example.com/denied/1")!

    /// The registered loopback redirect accepts any port; nothing listens on it.
    static let redirectURI = URL(string: "http://127.0.0.1:49152/callback")!

    static func requireIssuer() throws -> URL {
        try #require(issuer, "\(issuerVariable) is not set")
    }

    static func metadata() async throws -> AuthorizationServerMetadata {
        try await Discovery.fetchMetadata(issuer: try requireIssuer(), validation: .strict)
    }

    static func client(
        authentication: ClientAuthentication = .publicClient(clientID: publicClientID),
        minimumTokenLifetime: Duration = .seconds(5)
    ) async throws -> OAuthClient {
        let configuration = try ClientConfiguration(
            metadata: try await metadata(),
            authentication: authentication,
            minimumTokenLifetime: minimumTokenLifetime
        )
        return try OAuthClient(configuration: configuration)
    }

    /// A signed-in session obtained through the authorization code flow.
    struct Session {
        let client: OAuthClient
        let manager: TokenManager
        let store: any CredentialStore
        let account: CredentialAccount
        let response: TokenResponse

        var refreshToken: Secret? {
            get async { await manager.credential?.refreshToken }
        }
    }

    /// Signs in with the authorization code flow. Resources a refresh grant names later must be granted here.
    /// `prompt=consent` is needed for a refresh token: the
    /// server drops `offline_access` without it.
    static func signIn(
        scope: ScopeSet = fullScope,
        resources: [URL] = [allowedResource, deniedResource],
        store: any CredentialStore = InMemoryCredentialStore(),
        policy: any TokenAcceptancePolicy = AcceptAnyToken(),
        minimumTokenLifetime: Duration = .seconds(5)
    ) async throws -> Session {
        let client = try await client(minimumTokenLifetime: minimumTokenLifetime)
        let request = AuthorizationRequest(
            redirectURI: redirectURI, scope: scope, resources: resources, prompt: "consent")
        let response = try await client.authorize(request, using: RedirectFollowingUserAgent())
        let account = CredentialAccount(service: "IntegrationTests.\(UUID())", account: "user")
        let manager = TokenManager(client: client, store: store, account: account, acceptancePolicy: policy)
        try await manager.signIn(with: response, requestedScope: scope)
        return Session(client: client, manager: manager, store: store, account: account, response: response)
    }

    /// Approves or denies a pending device authorization through the server's test hook.
    static func decideDevice(userCode: String, approve: Bool) async throws {
        let issuer = try requireIssuer()
        var request = URLRequest(url: issuer.appending(path: approve ? "test/device/approve" : "test/device/deny"))
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONSerialization.data(withJSONObject: ["user_code": userCode])
        let (_, response) = try await URLSession(configuration: .ephemeral).data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode
        #expect(status == 200, "The device decision hook answered \(status ?? 0)")
    }
}

/// Runs `body` and returns the `PassportError` it throws, or `nil` when it succeeds.
func passportError(_ body: () async throws -> Void) async -> PassportError? {
    do {
        try await body()
        return nil
    } catch let error as PassportError {
        return error
    } catch {
        Issue.record("Unexpected error type: \(type(of: error))")
        return nil
    }
}

/// A user agent that follows the authorization server's redirects with HTTP and stops at the redirect URI,
/// returning it. The server's test interaction logs in and consents without a page.
struct RedirectFollowingUserAgent: UserAgent {
    func present(_ url: URL, redirectURI: URL) async throws -> URL {
        let session = URLSession(configuration: .ephemeral)  // keeps the interaction cookies for this flow only
        defer { session.finishTasksAndInvalidate() }
        let (_, response) = try await session.data(for: URLRequest(url: url), delegate: StopAtRedirectURI(redirectURI))
        guard
            let http = response as? HTTPURLResponse, (300..<400).contains(http.statusCode),
            let location = http.value(forHTTPHeaderField: "Location"),
            let target = URL(string: location, relativeTo: http.url)?.absoluteURL
        else {
            throw PassportError(.invalidResponse, errorDescription: "The server did not redirect to the redirect URI.")
        }
        return target
    }
}

private final class StopAtRedirectURI: NSObject, URLSessionTaskDelegate, Sendable {
    let redirectURI: URL

    init(_ redirectURI: URL) {
        self.redirectURI = redirectURI
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        let target = request.url
        let isRedirectURI =
            target?.host == redirectURI.host && target?.port == redirectURI.port && target?.path == redirectURI.path
        completionHandler(isRedirectURI ? nil : request)
    }
}
