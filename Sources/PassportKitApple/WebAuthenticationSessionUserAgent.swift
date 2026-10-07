#if canImport(AuthenticationServices) && !os(tvOS) && !os(watchOS)
    import AuthenticationServices
    import Foundation
    import PassportKit

    #if os(macOS)
        import AppKit
    #elseif os(iOS) || os(visionOS)
        import UIKit
    #endif

    /// A `AuthorizationUserAgent` backed by `ASWebAuthenticationSession` (RFC 8252 §6).
    ///
    /// Redirect URIs with a private-use scheme work on every supported version. An `https` redirect URI
    /// (a claimed URL) needs macOS 14.4, iOS 17.4 or visionOS 1.1; on older systems `present` throws
    /// `.invalidConfiguration`. A user who dismisses the sheet gets `.userCancelled`; cancelling the task
    /// closes the sheet and throws `CancellationError`.
    public struct WebAuthenticationSessionUserAgent: AuthorizationUserAgent {
        private let prefersEphemeralWebBrowserSession: Bool
        private let presentationAnchor: @MainActor @Sendable () -> ASPresentationAnchor
        private let launcher: any WebAuthenticationSessionLauncher

        /// Creates an agent.
        ///
        /// - Parameters:
        ///   - prefersEphemeralWebBrowserSession: Do not share cookies with the system browser, so the user is
        ///     always asked to sign in and no single sign-on session is created.
        ///   - presentationAnchor: Returns the window the sheet is presented from. The default, `nil`, is
        ///     the application's key window.
        public init(
            prefersEphemeralWebBrowserSession: Bool = false,
            presentationAnchor: (@MainActor @Sendable () -> ASPresentationAnchor)? = nil
        ) {
            self.init(
                prefersEphemeralWebBrowserSession: prefersEphemeralWebBrowserSession,
                presentationAnchor: presentationAnchor ?? { Self.keyWindow() },
                launcher: SystemWebAuthenticationSessionLauncher()
            )
        }

        init(
            prefersEphemeralWebBrowserSession: Bool,
            presentationAnchor: @escaping @MainActor @Sendable () -> ASPresentationAnchor,
            launcher: any WebAuthenticationSessionLauncher
        ) {
            self.prefersEphemeralWebBrowserSession = prefersEphemeralWebBrowserSession
            self.presentationAnchor = presentationAnchor
            self.launcher = launcher
        }

        /// Presents `url` and returns the callback URL for `redirectURI`.
        ///
        /// `redirectURI` must use a private-use scheme or `https`; `http` loopback redirects belong to
        /// ``LoopbackUserAgent``.
        public func present(_ url: URL, redirectURI: URL) async throws -> URL {
            let callback = try Self.callback(for: redirectURI)
            do {
                return try await launcher.authenticate(
                    url: url,
                    callback: callback,
                    prefersEphemeralWebBrowserSession: prefersEphemeralWebBrowserSession,
                    presentationAnchor: presentationAnchor
                )
            } catch {
                if Task.isCancelled { throw CancellationError() }
                throw Self.map(error)
            }
        }

        /// Derives the callback matcher from the redirect URI.
        static func callback(for redirectURI: URL) throws -> WebAuthenticationCallback {
            guard let scheme = redirectURI.scheme?.lowercased(), !scheme.isEmpty else {
                throw PassportError(.invalidConfiguration, detail: "The redirect URI has no scheme.")
            }
            switch scheme {
            case "https":
                guard let host = redirectURI.host, !host.isEmpty, !redirectURI.path.isEmpty else {
                    throw PassportError(
                        .invalidConfiguration,
                        detail: "An https redirect URI needs a host and a path."
                    )
                }
                return .https(host: host, path: redirectURI.path)
            case "http":
                throw PassportError(
                    .invalidConfiguration,
                    detail: "Use LoopbackUserAgent for http loopback redirect URIs."
                )
            default:
                return .scheme(scheme)
            }
        }

        /// Maps a session failure to a `PassportError`; the user dismissing the sheet is not an error of the flow.
        static func map(_ error: any Error) -> any Error {
            if error is PassportError || error is CancellationError { return error }
            if let sessionError = error as? ASWebAuthenticationSessionError {
                switch sessionError.code {
                case .canceledLogin:
                    return PassportError(.userCancelled, detail: "The user cancelled the sign-in.")
                case .presentationContextNotProvided, .presentationContextInvalid:
                    return PassportError(
                        .invalidConfiguration,
                        detail: "No window is available to present the sign-in.",
                        underlying: error
                    )
                @unknown default:
                    break
                }
            }
            return PassportError(
                .transportFailure,
                detail: "The web authentication session failed.",
                underlying: error
            )
        }

        /// The key window of the foreground application, or an empty anchor when there is none.
        @MainActor
        static func keyWindow() -> ASPresentationAnchor {
            #if os(macOS)
                return NSApplication.shared.keyWindow ?? NSApplication.shared.mainWindow ?? ASPresentationAnchor()
            #elseif os(iOS) || os(visionOS)
                let windows = UIApplication.shared.connectedScenes.compactMap { ($0 as? UIWindowScene)?.windows }
                    .flatMap { $0 }
                return windows.first { $0.isKeyWindow } ?? windows.first ?? ASPresentationAnchor()
            #else
                return ASPresentationAnchor()
            #endif
        }
    }
#endif
