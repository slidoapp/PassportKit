#if canImport(Network)
    import Foundation
    import PassportKit

    #if os(macOS)
        import AppKit
    #elseif os(iOS) || os(visionOS)
        import UIKit
    #endif

    /// A `AuthorizationUserAgent` that opens the authorization URL in the system browser and waits for the redirect on
    /// a running ``LoopbackRedirectListener`` (RFC 8252 §7.3).
    ///
    /// The agent ignores redirects whose `state` differs from the authorization URL's, so a stray request
    /// cannot end the flow.
    ///
    /// ```swift
    /// let listener = try await LoopbackRedirectListener.start()
    /// let request = AuthorizationRequest(redirectURI: listener.redirectURI, scope: scope)
    /// let tokens = try await client.authorize(request, using: LoopbackUserAgent(listener: listener))
    /// ```
    public struct LoopbackUserAgent: AuthorizationUserAgent {
        private let listener: LoopbackRedirectListener
        private let timeout: Duration
        private let openURL: @Sendable (URL) async throws -> Void

        /// Creates an agent for a listener that is already running.
        ///
        /// - Parameters:
        ///   - listener: The listener whose ``LoopbackRedirectListener/redirectURI`` the request uses.
        ///   - timeout: How long to wait for the redirect after the browser was opened.
        ///   - openURL: Opens a URL in the user's browser. The default uses `NSWorkspace` on macOS and
        ///     `UIApplication` on iOS and visionOS; on other platforms supply your own.
        public init(
            listener: LoopbackRedirectListener,
            timeout: Duration = .seconds(300),
            openURL: @escaping @Sendable (URL) async throws -> Void = LoopbackUserAgent.openInSystemBrowser
        ) {
            self.listener = listener
            self.timeout = timeout
            self.openURL = openURL
        }

        /// Opens `url` and returns the redirect the listener receives.
        ///
        /// - Throws: `PassportError` with `.invalidConfiguration` when `redirectURI` is not the listener's,
        ///   `.timedOut` when no redirect arrives, or `CancellationError`. The listener is stopped either way.
        public func present(_ url: URL, redirectURI: URL) async throws -> URL {
            guard redirectURI == listener.redirectURI else {
                listener.cancel()
                throw PassportError(
                    .invalidConfiguration,
                    detail: "The redirect URI is not the loopback listener's."
                )
            }
            do {
                try await openURL(url)
            } catch {
                listener.cancel()
                if error is CancellationError || error is PassportError { throw error }
                throw PassportError(
                    .invalidConfiguration,
                    detail: "The browser could not be opened.",
                    underlying: error
                )
            }
            // Only a redirect that carries this request's `state` may end the wait; the client checks it again.
            let state = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?
                .first { $0.name == "state" }?.value
            return try await listener.waitForCallback(timeout: timeout) { callback in
                guard let state else { return true }
                return URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems?
                    .contains { $0.name == "state" && $0.value == state } ?? false
            }
        }

        /// Opens `url` with the platform's default browser.
        @Sendable
        public static func openInSystemBrowser(_ url: URL) async throws {
            #if os(macOS)
                let opened = await MainActor.run { NSWorkspace.shared.open(url) }
            #elseif os(iOS) || os(visionOS)
                let opened = await openOnMainActor(url)
            #else
                let opened = false
            #endif
            guard opened else {
                throw PassportError(
                    .invalidConfiguration,
                    detail: "The system browser could not be opened on this platform."
                )
            }
        }

        #if os(iOS) || os(visionOS)
            @MainActor
            private static func openOnMainActor(_ url: URL) async -> Bool {
                await UIApplication.shared.open(url, options: [:])
            }
        #endif
    }
#endif
