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
    /// (or your own code) call ``waitForCallback(timeout:accept:)``.
    ///
    /// The listener binds `127.0.0.1` on an ephemeral port only. It answers every request itself and
    /// returns the first `GET` request for ``redirectURI``'s path whose `Host` is the loopback address on
    /// this port, whose query has `state` and `code` or `error`, that no `Sec-Fetch-Mode` or `Sec-Fetch-Dest`
    /// header marks as a background request, and that the `accept` predicate of
    /// ``waitForCallback(timeout:accept:)`` allows. Other requests get an error status and the listener keeps
    /// waiting, so a stray request from a web page cannot use up the redirect. At most 8 connections are open
    /// at once and each is closed after 5 seconds on the injected clock. A listener is single use: it stops
    /// after the callback, a timeout, a failure, or ``cancel()``, which also closes open connections.
    ///
    /// A listener that is never waited on stays open until ``cancel()`` or until the last reference is
    /// released, which also stops it.
    public final class LoopbackRedirectListener: Sendable {
        /// `http://127.0.0.1:<port><path>` with the port the system assigned.
        public let redirectURI: URL

        private let listener: NWListener
        private let clock: any Clock<Duration>
        private let callbacks: AsyncStream<URL>
        private let callbackContinuation: AsyncStream<URL>.Continuation
        private let connections: LoopbackConnections
        private let acceptor: OSAllocatedUnfairLock<@Sendable (URL) -> Bool>

        /// Starts listening on an ephemeral loopback port and returns once it is ready.
        ///
        /// - Parameters:
        ///   - path: The redirect path, such as `/callback`. It must start with `/` and have no query.
        ///   - clock: Times ``waitForCallback(timeout:accept:)``.
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
            let connections = LoopbackConnections()
            let acceptor = OSAllocatedUnfairLock<@Sendable (URL) -> Bool>(initialState: { _ in true })
            listener.newConnectionHandler = { connection in
                guard finished.withLock({ !$0 }) else { return connection.cancel() }
                LoopbackConnection.serve(
                    connection,
                    context: LoopbackConnection.Context(
                        path: path,
                        port: port.withLock { $0 },
                        clock: clock,
                        connections: connections,
                        accept: { url in acceptor.withLock { $0 }(url) },
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
                            connections.closeAll()
                        }
                    )
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
                callbackContinuation: continuation,
                connections: connections,
                acceptor: acceptor
            )
        }

        private init(
            redirectURI: URL,
            listener: NWListener,
            clock: any Clock<Duration>,
            callbacks: AsyncStream<URL>,
            callbackContinuation: AsyncStream<URL>.Continuation,
            connections: LoopbackConnections,
            acceptor: OSAllocatedUnfairLock<@Sendable (URL) -> Bool>
        ) {
            self.redirectURI = redirectURI
            self.listener = listener
            self.clock = clock
            self.callbacks = callbacks
            self.callbackContinuation = callbackContinuation
            self.connections = connections
            self.acceptor = acceptor
        }

        deinit { cancel() }

        /// Waits for the redirect and returns its full URL, query included.
        ///
        /// The listener is stopped when this returns or throws. Call it once.
        ///
        /// - Parameters:
        ///   - timeout: How long to wait, measured on the injected clock.
        ///   - accept: Decides whether a request that has the shape of an authorization response is the one
        ///     the flow expects, for example by comparing its `state`. A request it refuses gets status 400
        ///     and the listener keeps waiting. It runs on a background queue.
        /// - Throws: `PassportError` with `.timedOut` when `timeout` passes on the injected clock, or
        ///   `CancellationError` when the task is cancelled or ``cancel()`` is called first.
        public func waitForCallback(
            timeout: Duration = .seconds(300),
            accept: @escaping @Sendable (URL) -> Bool = { _ in true }
        ) async throws -> URL {
            acceptor.withLock { $0 = accept }
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

        /// Stops the listener and closes open connections. Pending and later waits end with
        /// `CancellationError`. Safe to call repeatedly.
        public func cancel() {
            listener.cancel()
            connections.closeAll()
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
