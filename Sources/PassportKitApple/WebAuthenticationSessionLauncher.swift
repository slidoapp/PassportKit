#if canImport(AuthenticationServices) && !os(tvOS) && !os(watchOS)
    import AuthenticationServices
    import Foundation
    import PassportKit

    /// How a session recognises the redirect.
    enum WebAuthenticationCallback: Equatable, Sendable {
        /// A private-use URI scheme (RFC 8252 §7.1).
        case scheme(String)
        /// A claimed `https` URL (RFC 8252 §7.2).
        case https(host: String, path: String)
    }

    /// The part of `ASWebAuthenticationSession` the user agent depends on, so the mapping logic can be
    /// tested without presenting UI.
    protocol WebAuthenticationSessionLauncher: Sendable {
        /// Runs one session and returns the callback URL, or throws the session's raw error. Cancelling the
        /// calling task must end the session.
        func authenticate(
            url: URL,
            callback: WebAuthenticationCallback,
            prefersEphemeralWebBrowserSession: Bool,
            presentationAnchor: @escaping @MainActor @Sendable () -> ASPresentationAnchor
        ) async throws -> URL
    }

    struct SystemWebAuthenticationSessionLauncher: WebAuthenticationSessionLauncher {
        func authenticate(
            url: URL,
            callback: WebAuthenticationCallback,
            prefersEphemeralWebBrowserSession: Bool,
            presentationAnchor: @escaping @MainActor @Sendable () -> ASPresentationAnchor
        ) async throws -> URL {
            try await SessionRun.run(
                url: url,
                callback: callback,
                prefersEphemeral: prefersEphemeralWebBrowserSession,
                presentationAnchor: presentationAnchor
            )
        }
    }

    /// One `ASWebAuthenticationSession`, kept alive until its completion handler runs.
    @MainActor
    private final class SessionRun: NSObject, ASWebAuthenticationPresentationContextProviding {
        private var session: ASWebAuthenticationSession?
        private let presentationAnchor: @MainActor @Sendable () -> ASPresentationAnchor

        private init(presentationAnchor: @escaping @MainActor @Sendable () -> ASPresentationAnchor) {
            self.presentationAnchor = presentationAnchor
        }

        static func run(
            url: URL,
            callback: WebAuthenticationCallback,
            prefersEphemeral: Bool,
            presentationAnchor: @escaping @MainActor @Sendable () -> ASPresentationAnchor
        ) async throws -> URL {
            try Task.checkCancellation()
            let run = SessionRun(presentationAnchor: presentationAnchor)
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    let handler: @Sendable (URL?, (any Error)?) -> Void = { callbackURL, error in
                        if let callbackURL {
                            continuation.resume(returning: callbackURL)
                        } else {
                            continuation.resume(throwing: error ?? PassportError(.invalidResponse))
                        }
                    }
                    do {
                        let session = try run.makeSession(url: url, callback: callback, handler: handler)
                        session.prefersEphemeralWebBrowserSession = prefersEphemeral
                        session.presentationContextProvider = run
                        run.session = session
                        if !session.start() {
                            run.session = nil
                            continuation.resume(
                                throwing: PassportError(
                                    .invalidConfiguration,
                                    detail: "The web authentication session could not start."
                                )
                            )
                        }
                    } catch {
                        continuation.resume(throwing: error)
                    }
                }
            } onCancel: {
                // The session completes with `canceledLogin` after this, which the caller turns into
                // `CancellationError` because the task is cancelled.
                Task { @MainActor in run.session?.cancel() }
            }
        }

        private func makeSession(
            url: URL,
            callback: WebAuthenticationCallback,
            handler: @escaping @Sendable (URL?, (any Error)?) -> Void
        ) throws -> ASWebAuthenticationSession {
            switch callback {
            case .scheme(let scheme):
                return ASWebAuthenticationSession(url: url, callbackURLScheme: scheme, completionHandler: handler)
            case .https(let host, let path):
                guard #available(macOS 14.4, iOS 17.4, visionOS 1.1, *) else {
                    throw PassportError(
                        .invalidConfiguration,
                        detail: "An https redirect URI needs macOS 14.4, iOS 17.4 or visionOS 1.1."
                    )
                }
                return ASWebAuthenticationSession(
                    url: url,
                    callback: .https(host: host, path: path),
                    completionHandler: handler
                )
            }
        }

        nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
            // AuthenticationServices asks on the main thread.
            MainActor.assumeIsolated { presentationAnchor() }
        }
    }
#endif
