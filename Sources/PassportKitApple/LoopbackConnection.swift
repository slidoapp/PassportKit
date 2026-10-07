#if canImport(Network)
    import Foundation
    import Network
    import os

    /// Serves one accepted loopback connection: reads a request head, answers it and closes.
    enum LoopbackConnection {
        private static let successPage = """
            <!doctype html><html lang="en"><head><meta charset="utf-8"><title>Done</title></head>\
            <body><p>You can return to the app.</p></body></html>
            """

        /// How long an accepted connection may stay open, so idle or slow connections cannot hold the listener.
        static let timeout: Duration = .seconds(5)

        /// What a connection needs to know about the listener that accepted it.
        struct Context: Sendable {
            var path: String
            var port: UInt16
            var clock: any Clock<Duration>
            var connections: LoopbackConnections
            /// Decides whether a well-formed redirect belongs to the flow in progress.
            var accept: @Sendable (URL) -> Bool
            /// Called for the redirect; returns whether it is the first one.
            var claim: @Sendable () -> Bool
            /// Receives the full URL of the redirect request after the answer was sent.
            var deliver: @Sendable (URL) -> Void
        }

        /// Reads the request, answers it, and delivers the redirect URL after the answer was sent.
        ///
        /// The connection is closed after ``timeout`` and when the listener stops.
        static func serve(_ connection: NWConnection, context: Context) {
            guard context.connections.admit(connection) else { return connection.cancel() }
            let deadline = Task { [clock = context.clock] in
                try await clock.sleep(for: timeout)
                connection.cancel()
            }
            connection.stateUpdateHandler = { state in
                switch state {
                case .failed: connection.cancel()
                case .cancelled:
                    deadline.cancel()
                    context.connections.release(connection)
                default: break
                }
            }
            connection.start(queue: DispatchQueue(label: "passportkit.loopback.connection"))
            receive(connection, buffer: Data(), context: context)
        }

        private static func receive(_ connection: NWConnection, buffer: Data, context: Context) {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 2048) { data, _, isComplete, error in
                guard error == nil else { return connection.cancel() }
                let received = buffer + (data ?? Data())
                switch LoopbackRequestHead.parse(received) {
                case .incomplete:
                    guard !isComplete, data != nil else { return connection.cancel() }
                    receive(connection, buffer: received, context: context)
                case .tooLarge:
                    respond(connection, status: 431)
                case .malformed:
                    respond(connection, status: 400)
                case .complete(let head):
                    switch LoopbackRoute.route(head, path: context.path, port: context.port) {
                    case .reject(let status):
                        respond(connection, status: status)
                    case .callback(let target):
                        guard let url = URL(string: "http://127.0.0.1:\(context.port)\(target)"), context.accept(url)
                        else { return respond(connection, status: 400) }
                        guard context.claim() else { return connection.cancel() }
                        respond(connection, status: 200) { context.deliver(url) }
                    }
                }
            }
        }

        /// Writes a complete response and closes. The body is fixed text: nothing from the request is echoed.
        private static func respond(
            _ connection: NWConnection,
            status: Int,
            afterSend: (@Sendable () -> Void)? = nil
        ) {
            let reason: String
            switch status {
            case 200: reason = "OK"
            case 404: reason = "Not Found"
            case 405: reason = "Method Not Allowed"
            case 431: reason = "Request Header Fields Too Large"
            default: reason = "Bad Request"
            }
            let body = status == 200 ? successPage : reason
            let head =
                "HTTP/1.1 \(status) \(reason)\r\n"
                + "Content-Type: \(status == 200 ? "text/html" : "text/plain"); charset=utf-8\r\n"
                + "Content-Length: \(body.utf8.count)\r\n"
                + "Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n"
                + "Content-Security-Policy: default-src 'none'\r\n"
                + "Connection: close\r\n\r\n"
            connection.send(
                content: Data((head + body).utf8),
                contentContext: .finalMessage,
                isComplete: true,
                completion: .contentProcessed { _ in
                    connection.cancel()
                    afterSend?()
                }
            )
        }
    }

    /// The connections a listener has accepted and not yet closed.
    final class LoopbackConnections: Sendable {
        /// More simultaneous connections than a single browser needs for one redirect.
        static let maximum = 8

        private struct State {
            var open: [ObjectIdentifier: NWConnection] = [:]
            var isClosed = false
        }

        private let state = OSAllocatedUnfairLock(initialState: State())

        /// Registers a connection. Returns `false` when the listener stopped or too many are open.
        func admit(_ connection: NWConnection) -> Bool {
            state.withLock { state in
                guard !state.isClosed, state.open.count < Self.maximum else { return false }
                state.open[ObjectIdentifier(connection)] = connection
                return true
            }
        }

        func release(_ connection: NWConnection) {
            state.withLock { _ = $0.open.removeValue(forKey: ObjectIdentifier(connection)) }
        }

        /// Cancels every open connection and refuses later ones.
        func closeAll() {
            let open = state.withLock { state -> [NWConnection] in
                state.isClosed = true
                return Array(state.open.values)
            }
            for connection in open { connection.cancel() }
        }
    }
#endif
