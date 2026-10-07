#if canImport(AuthenticationServices) && !os(tvOS) && !os(watchOS)
    import AuthenticationServices
    import Foundation
    import PassportKit
    import Testing

    @testable import PassportKitApple

    @Suite("Web authentication session user agent")
    struct WebAuthenticationSessionUserAgentTests {
        private struct Launcher: WebAuthenticationSessionLauncher {
            var result: Result<URL, any Error>
            var record: @Sendable (WebAuthenticationCallback, Bool) -> Void = { _, _ in }

            func authenticate(
                url: URL,
                callback: WebAuthenticationCallback,
                prefersEphemeralWebBrowserSession: Bool,
                presentationAnchor: @escaping @MainActor @Sendable () -> ASPresentationAnchor
            ) async throws -> URL {
                record(callback, prefersEphemeralWebBrowserSession)
                return try result.get()
            }
        }

        private let authorization = URL(string: "https://as.example.com/authorize")!

        private func agent(
            _ result: Result<URL, any Error>,
            ephemeral: Bool = false,
            record: @escaping @Sendable (WebAuthenticationCallback, Bool) -> Void = { _, _ in }
        ) -> WebAuthenticationSessionUserAgent {
            WebAuthenticationSessionUserAgent(
                prefersEphemeralWebBrowserSession: ephemeral,
                presentationAnchor: { ASPresentationAnchor() },
                launcher: Launcher(result: result, record: record)
            )
        }

        @Test func canceledLoginBecomesUserCancelled() async throws {
            let cancelled = agent(.failure(ASWebAuthenticationSessionError(.canceledLogin)))
            let redirect = try #require(URL(string: "com.example.app:/callback"))
            await #expect(throws: PassportError(.userCancelled)) {
                _ = try await cancelled.present(authorization, redirectURI: redirect)
            }
        }

        @Test func contextErrorsBecomeInvalidConfiguration() async throws {
            let missing = agent(.failure(ASWebAuthenticationSessionError(.presentationContextNotProvided)))
            let redirect = try #require(URL(string: "com.example.app:/callback"))
            await #expect(throws: PassportError(.invalidConfiguration)) {
                _ = try await missing.present(authorization, redirectURI: redirect)
            }
        }

        @Test func otherErrorsBecomeTransportFailures() async throws {
            struct Unknown: Error {}
            let failing = agent(.failure(Unknown()))
            let redirect = try #require(URL(string: "com.example.app:/callback"))
            await #expect(throws: PassportError(.transportFailure)) {
                _ = try await failing.present(authorization, redirectURI: redirect)
            }
        }

        @Test func returnsTheCallbackURL() async throws {
            let callback = try #require(URL(string: "com.example.app:/callback?code=abc"))
            let succeeding = agent(.success(callback))
            let redirect = try #require(URL(string: "com.example.app:/callback"))
            #expect(try await succeeding.present(authorization, redirectURI: redirect) == callback)
        }

        @Test func choosesTheCallbackKindFromTheRedirectURI() throws {
            let scheme = try #require(URL(string: "Com.Example.App:/callback"))
            #expect(try WebAuthenticationSessionUserAgent.callback(for: scheme) == .scheme("com.example.app"))
            let claimed = try #require(URL(string: "https://app.example.com/oauth/callback"))
            #expect(
                try WebAuthenticationSessionUserAgent.callback(for: claimed)
                    == .https(host: "app.example.com", path: "/oauth/callback")
            )
            let loopback = try #require(URL(string: "http://127.0.0.1:5000/callback"))
            #expect(throws: PassportError(.invalidConfiguration)) {
                try WebAuthenticationSessionUserAgent.callback(for: loopback)
            }
            let noPath = try #require(URL(string: "https://app.example.com"))
            #expect(throws: PassportError(.invalidConfiguration)) {
                try WebAuthenticationSessionUserAgent.callback(for: noPath)
            }
        }

        @Test func passesTheOptionsToTheSession() async throws {
            let recorded = RecordedOptions()
            let configured = agent(.success(authorization), ephemeral: true) { callback, ephemeral in
                recorded.set(callback, ephemeral)
            }
            let redirect = try #require(URL(string: "com.example.app:/callback"))
            _ = try await configured.present(authorization, redirectURI: redirect)
            #expect(recorded.value?.0 == .scheme("com.example.app"))
            #expect(recorded.value?.1 == true)
        }

        @Test func cancelledTaskThrowsCancellationError() async throws {
            let cancelled = agent(.failure(ASWebAuthenticationSessionError(.canceledLogin)))
            let redirect = try #require(URL(string: "com.example.app:/callback"))
            let task = Task {
                while !Task.isCancelled { await Task.yield() }
                return try await cancelled.present(authorization, redirectURI: redirect)
            }
            task.cancel()
            await #expect(throws: CancellationError.self) { try await task.value }
        }
    }

    private final class RecordedOptions: Sendable {
        private let lock = NSLock()
        nonisolated(unsafe) private var stored: (WebAuthenticationCallback, Bool)?  // guarded by `lock`
        var value: (WebAuthenticationCallback, Bool)? { lock.withLock { stored } }
        func set(_ callback: WebAuthenticationCallback, _ ephemeral: Bool) {
            lock.withLock { stored = (callback, ephemeral) }
        }
    }
#endif
