import Foundation
import PassportKit

// The code samples of Sources/PassportKit/PassportKit.docc/NativeAppRedirects.md, compiled so that they
// follow the real API. They are never run. When you change a sample in the article, change it here.

enum DocumentationSnippets {
    @MainActor
    static func webAuthenticationSession(client: OAuthClient) async throws -> TokenResponse {
        let request = AuthorizationRequest(
            redirectURI: URL(string: "com.example.app:/callback")!,
            scope: ["openid", "offline_access"])
        return try await client.authorize(request, using: .webAuthenticationSession())
    }

    static func loopback(client: OAuthClient) async throws -> TokenResponse {
        let listener = try await LoopbackRedirectListener.start()
        let request = AuthorizationRequest(redirectURI: listener.redirectURI, scope: ["openid"])
        return try await client.authorize(request, using: LoopbackUserAgent(listener: listener))
    }
}
