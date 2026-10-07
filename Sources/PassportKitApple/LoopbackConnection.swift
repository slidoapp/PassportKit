#if canImport(Network)
    import Foundation
    import Network

    /// Serves one accepted loopback connection: reads a request head, answers it and closes.
    enum LoopbackConnection {
        private static let successPage = """
            <!doctype html><html lang="en"><head><meta charset="utf-8"><title>Done</title></head>\
            <body><p>You can return to the app.</p></body></html>
            """

        /// Reads the request, answers it, and calls `deliver` with the redirect URL after the answer was sent.
        ///
        /// - Parameters:
        ///   - claim: Called for a request that is the redirect; returns whether it is the first one.
        ///   - deliver: Receives the full URL of the redirect request.
        static func serve(
            _ connection: NWConnection,
            path: String,
            port: UInt16,
            claim: @escaping @Sendable () -> Bool,
            deliver: @escaping @Sendable (URL) -> Void
        ) {
            connection.stateUpdateHandler = { state in
                if case .failed = state { connection.cancel() }
            }
            connection.start(queue: DispatchQueue(label: "passportkit.loopback.connection"))
            receive(connection, buffer: Data(), path: path, port: port, claim: claim, deliver: deliver)
        }

        private static func receive(
            _ connection: NWConnection,
            buffer: Data,
            path: String,
            port: UInt16,
            claim: @escaping @Sendable () -> Bool,
            deliver: @escaping @Sendable (URL) -> Void
        ) {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 2048) { data, _, isComplete, error in
                guard error == nil else { return connection.cancel() }
                let received = buffer + (data ?? Data())
                switch LoopbackRequestHead.parse(received) {
                case .incomplete:
                    guard !isComplete, data != nil else { return connection.cancel() }
                    receive(connection, buffer: received, path: path, port: port, claim: claim, deliver: deliver)
                case .tooLarge:
                    respond(connection, status: 431)
                case .malformed:
                    respond(connection, status: 400)
                case .complete(let head):
                    switch LoopbackRoute.route(head, path: path, port: port) {
                    case .reject(let status):
                        respond(connection, status: status)
                    case .callback(let target):
                        guard let url = URL(string: "http://127.0.0.1:\(port)\(target)") else {
                            return respond(connection, status: 400)
                        }
                        guard claim() else { return connection.cancel() }
                        respond(connection, status: 200) { deliver(url) }
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
#endif
