#if canImport(Network) && canImport(AuthenticationServices) && os(macOS)
    import Foundation
    import PassportKit
    import PassportKitApple

    // The code samples of Sources/PassportKit/PassportKit.docc/NativeAppRedirects.md, compiled so that they
    // follow the real API. They are never run. When you change a sample in the article, change it here.

    enum DocumentationSnippets {
        @MainActor
        static func webAuthenticationSession(client: OAuthClient) async throws -> TokenResponse {
            let request = AuthorizationRequest(
                redirectURI: URL(string: "com.example.app:/callback")!,
                scope: ["openid", "offline_access"])
            let userAgent = WebAuthenticationSessionUserAgent(prefersEphemeralWebBrowserSession: false)
            return try await client.authorize(request, using: userAgent)
        }

        static func loopback(client: OAuthClient) async throws -> TokenResponse {
            let listener = try await LoopbackRedirectListener.start()
            let request = AuthorizationRequest(redirectURI: listener.redirectURI, scope: ["openid"])
            return try await client.authorize(request, using: LoopbackUserAgent(listener: listener))
        }
    }
#endif
