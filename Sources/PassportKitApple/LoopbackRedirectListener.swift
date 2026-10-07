#if canImport(Network)
    import Foundation
    import Network
    import PassportKit
    import os

    /// A one-shot HTTP listener on the IPv4 loopback address that receives an authorization response
    /// (RFC 8252 §7.3).
    ///
    /// The redirect URI must carry the port the listener actually got, so the flow has two steps: start
    /// the listener, put ``redirectURI`` into the `AuthorizationRequest`, then let a ``LoopbackUserAgent``
    /// (or your own code) call ``waitForCallback(timeout:)``.
    ///
    /// The listener binds `127.0.0.1` on an ephemeral port only. It answers every request itself and
    /// returns the first `GET` request for ``redirectURI``'s path whose `Host` is the loopback address on
    /// this port; other requests get an error status and the listener keeps waiting. A listener is single
    /// use: it stops after the callback, a timeout, a failure, or ``cancel()``.
    public final class LoopbackRedirectListener: Sendable {
        /// `http://127.0.0.1:<port><path>` with the port the system assigned.
        public let redirectURI: URL

        private let listener: NWListener
        private let clock: any Clock<Duration>
        private let callbacks: AsyncStream<URL>
        private let callbackContinuation: AsyncStream<URL>.Continuation

        /// Starts listening on an ephemeral loopback port and returns once it is ready.
        ///
        /// - Parameters:
        ///   - path: The redirect path, such as `/callback`. It must start with `/` and have no query.
        ///   - clock: Times ``waitForCallback(timeout:)``.
        /// - Throws: `PassportError` with `.invalidConfiguration` for an invalid `path`, and
        ///   `.transportFailure` when the socket cannot be opened.
        public static func start(
            path: String = "/callback",
            clock: any Clock<Duration> = ContinuousClock()
        ) async throws -> LoopbackRedirectListener {
            guard path.hasPrefix("/"), path.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F && $0 != 0x3F && $0 != 0x23 })
            else {
                throw PassportError(
                    .invalidConfiguration,
                    detail: "The loopback path must start with / and contain no query or fragment."
                )
            }
            let parameters = NWParameters.tcp
            parameters.requiredInterfaceType = .loopback
            parameters.requiredLocalEndpoint = .hostPort(host: .ipv4(.loopback), port: .any)
            let listener: NWListener
            do {
                listener = try NWListener(using: parameters)
            } catch {
                throw PassportError(
                    .transportFailure,
                    detail: "The loopback listener could not be created.",
                    underlying: error
                )
            }
            let (callbacks, continuation) = AsyncStream<URL>.makeStream(bufferingPolicy: .bufferingNewest(1))
            let port = OSAllocatedUnfairLock<UInt16>(initialState: 0)
            let finished = OSAllocatedUnfairLock<Bool>(initialState: false)
            listener.newConnectionHandler = { connection in
                guard finished.withLock({ !$0 }) else { return connection.cancel() }
                LoopbackConnection.serve(
                    connection,
                    path: path,
                    port: port.withLock { $0 },
                    // Only the first matching request is the callback; later ones are dropped.
                    claim: {
                        finished.withLock { done in
                            defer { done = true }
                            return !done
                        }
                    },
                    deliver: { url in
                        continuation.yield(url)
                        continuation.finish()
                        listener.cancel()
                    }
                )
            }
            try await ListenerStartup.run(listener) { assigned in port.withLock { $0 = assigned } }
            let assignedPort = port.withLock { $0 }
            guard let redirectURI = URL(string: "http://127.0.0.1:\(assignedPort)\(path)") else {
                listener.cancel()
                throw PassportError(.invalidConfiguration, detail: "The loopback path is not valid.")
            }
            return LoopbackRedirectListener(
                redirectURI: redirectURI,
                listener: listener,
                clock: clock,
                callbacks: callbacks,
                callbackContinuation: continuation
            )
        }

        private init(
            redirectURI: URL,
            listener: NWListener,
            clock: any Clock<Duration>,
            callbacks: AsyncStream<URL>,
            callbackContinuation: AsyncStream<URL>.Continuation
        ) {
            self.redirectURI = redirectURI
            self.listener = listener
            self.clock = clock
            self.callbacks = callbacks
            self.callbackContinuation = callbackContinuation
        }

        /// Waits for the redirect and returns its full URL, query included.
        ///
        /// The listener is stopped when this returns or throws. Call it once.
        ///
        /// - Throws: `PassportError` with `.timedOut` when `timeout` passes on the injected clock, or
        ///   `CancellationError` when the task is cancelled or ``cancel()`` is called first.
        public func waitForCallback(timeout: Duration = .seconds(300)) async throws -> URL {
            defer { cancel() }
            return try await withTaskCancellationHandler {
                try await withThrowingTaskGroup(of: URL.self) { group in
                    let callbacks = callbacks
                    let clock = clock
                    group.addTask {
                        for await url in callbacks { return url }
                        throw CancellationError()
                    }
                    group.addTask {
                        try await clock.sleep(for: timeout)
                        throw PassportError(
                            .timedOut,
                            recovery: .reauthenticate,
                            detail: "The redirect did not arrive in time."
                        )
                    }
                    defer { group.cancelAll() }
                    guard let url = try await group.next() else { throw CancellationError() }
                    return url
                }
            } onCancel: {
                cancel()
            }
        }

        /// Stops the listener. Pending and later waits end with `CancellationError`. Safe to call repeatedly.
        public func cancel() {
            listener.cancel()
            callbackContinuation.finish()
        }
    }

    /// Waits for an `NWListener` to become ready.
    private enum ListenerStartup {
        static func run(_ listener: NWListener, assignPort: @escaping @Sendable (UInt16) -> Void) async throws {
            let resumed = OSAllocatedUnfairLock<Bool>(initialState: false)
            try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                    // The state handler can fire more than once; only the first terminal state resumes.
                    @Sendable func finish(_ result: Result<Void, any Error>) {
                        let first = resumed.withLock { done in
                            defer { done = true }
                            return !done
                        }
                        if first { continuation.resume(with: result) }
                    }
                    listener.stateUpdateHandler = { state in
                        switch state {
                        case .ready:
                            guard let port = listener.port?.rawValue else {
                                listener.cancel()
                                return finish(.failure(PassportError(.transportFailure)))
                            }
                            assignPort(port)
                            finish(.success(()))
                        case .failed(let error):
                            listener.cancel()
                            finish(
                                .failure(
                                    PassportError(
                                        .transportFailure,
                                        detail: "The loopback listener failed to start.",
                                        underlying: error
                                    )
                                )
                            )
                        case .cancelled:
                            finish(.failure(CancellationError()))
                        default:
                            break
                        }
                    }
                    listener.start(queue: DispatchQueue(label: "passportkit.loopback.listener"))
                }
            } onCancel: {
                listener.cancel()
            }
        }
    }
#endif
