#if canImport(Network)
    import Foundation
    import Network
    import PassportKit
    import PassportKitTesting
    import Testing

    @testable import PassportKitApple

    /// Talks to the real listener over the loopback interface. No external network is involved.
    @Suite("Loopback redirect listener", .timeLimit(.minutes(1)))
    struct LoopbackRedirectListenerTests {
        private let session = URLSession(configuration: .ephemeral)

        private func url(_ listener: LoopbackRedirectListener, _ target: String) throws -> URL {
            try #require(URL(string: "http://127.0.0.1:\(listener.redirectURI.port ?? 0)\(target)"))
        }

        @Test func redirectURIUsesTheLoopbackAddressAndAnEphemeralPort() async throws {
            let listener = try await LoopbackRedirectListener.start(path: "/done")
            defer { listener.cancel() }
            #expect(listener.redirectURI.scheme == "http")
            #expect(listener.redirectURI.host == "127.0.0.1")
            #expect(listener.redirectURI.path == "/done")
            #expect((listener.redirectURI.port ?? 0) > 0)
        }

        @Test func returnsTheRedirectWithItsQuery() async throws {
            let listener = try await LoopbackRedirectListener.start()
            let waiting = Task { try await listener.waitForCallback() }
            let target = try url(listener, "/callback?code=abc&state=xyz")
            let (body, response) = try await session.data(from: target)
            let http = try #require(response as? HTTPURLResponse)
            #expect(http.statusCode == 200)
            #expect(http.value(forHTTPHeaderField: "Connection") == "close")
            let page = String(decoding: body, as: UTF8.self)
            #expect(page.contains("return to the app"))
            #expect(!page.contains("abc"))
            #expect(try await waiting.value == target)
        }

        @Test func answers404ForOtherPathsAndKeepsWaiting() async throws {
            let listener = try await LoopbackRedirectListener.start()
            let waiting = Task { try await listener.waitForCallback() }
            let (_, other) = try await session.data(from: try url(listener, "/favicon.ico"))
            #expect((other as? HTTPURLResponse)?.statusCode == 404)
            let target = try url(listener, "/callback?code=1&state=s")
            let (_, response) = try await session.data(from: target)
            #expect((response as? HTTPURLResponse)?.statusCode == 200)
            #expect(try await waiting.value == target)
        }

        @Test func rejectsAnotherHostAndKeepsWaiting() async throws {
            let listener = try await LoopbackRedirectListener.start()
            let waiting = Task { try await listener.waitForCallback() }
            let port = try #require(listener.redirectURI.port)
            let reply = try await RawClient.send(
                "GET /callback?code=1&state=s HTTP/1.1\r\nHost: attacker.example:\(port)\r\n\r\n",
                toPort: port
            )
            #expect(reply.hasPrefix("HTTP/1.1 400"))
            let target = try url(listener, "/callback?code=2&state=s")
            _ = try await session.data(from: target)
            #expect(try await waiting.value == target)
        }

        @Test func rejectsOtherMethods() async throws {
            let listener = try await LoopbackRedirectListener.start()
            defer { listener.cancel() }
            let port = try #require(listener.redirectURI.port)
            let reply = try await RawClient.send(
                "POST /callback HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\nContent-Length: 0\r\n\r\n",
                toPort: port
            )
            #expect(reply.hasPrefix("HTTP/1.1 405"))
        }

        @Test func rejectsOversizedRequestsAndKeepsWaiting() async throws {
            let listener = try await LoopbackRedirectListener.start()
            let waiting = Task { try await listener.waitForCallback() }
            let port = try #require(listener.redirectURI.port)
            let padding = String(repeating: "a", count: 16 * 1024)
            let reply = try await RawClient.send(
                "GET /callback?code=1&state=s HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\nX-Padding: \(padding)\r\n\r\n",
                toPort: port
            )
            #expect(reply.hasPrefix("HTTP/1.1 431"))
            let target = try url(listener, "/callback?code=2&state=s")
            _ = try await session.data(from: target)
            #expect(try await waiting.value == target)
        }

        @Test func takesOnlyTheFirstRedirect() async throws {
            let listener = try await LoopbackRedirectListener.start()
            let waiting = Task { try await listener.waitForCallback() }
            let first = try url(listener, "/callback?code=first&state=s")
            _ = try await session.data(from: first)
            #expect(try await waiting.value == first)
            await #expect(throws: (any Error).self) { _ = try await session.data(from: first) }
        }

        @Test func timesOutOnTheInjectedClock() async throws {
            let clock = ManualClock()
            let listener = try await LoopbackRedirectListener.start(clock: clock)
            let port = try #require(listener.redirectURI.port)
            let waiting = Task { try await listener.waitForCallback(timeout: .seconds(300)) }
            #expect(await clock.advanceToNextSleeper() == .seconds(300))
            await #expect(throws: PassportError(.timedOut, recovery: .reauthenticate)) { try await waiting.value }
            // The listener is closed afterwards.
            await #expect(throws: (any Error).self) {
                _ = try await RawClient.send("GET / HTTP/1.1\r\n\r\n", toPort: port)
            }
        }

        @Test func cancellationStopsTheListener() async throws {
            let clock = ManualClock()
            let listener = try await LoopbackRedirectListener.start(clock: clock)
            let port = try #require(listener.redirectURI.port)
            let waiting = Task { try await listener.waitForCallback() }
            await clock.waitForSleeper()
            waiting.cancel()
            await #expect(throws: CancellationError.self) { try await waiting.value }
            await #expect(throws: (any Error).self) {
                _ = try await RawClient.send("GET / HTTP/1.1\r\n\r\n", toPort: port)
            }
        }

        @Test func ignoresStrayRequestsThatDoNotLookLikeAResponse() async throws {
            let listener = try await LoopbackRedirectListener.start()
            let waiting = Task { try await listener.waitForCallback() }
            let port = try #require(listener.redirectURI.port)
            for target in ["/callback", "/callback?code=1"] {
                let reply = try await RawClient.send(
                    "GET \(target) HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\n\r\n", toPort: port)
                #expect(reply.hasPrefix("HTTP/1.1 400"))
            }
            let background = try await RawClient.send(
                "GET /callback?code=1&state=s HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\nSec-Fetch-Mode: no-cors\r\n\r\n",
                toPort: port
            )
            #expect(background.hasPrefix("HTTP/1.1 400"))
            let target = try url(listener, "/callback?code=2&state=s")
            _ = try await session.data(from: target)
            #expect(try await waiting.value == target)
        }

        @Test func skipsRedirectsTheAcceptPredicateRefuses() async throws {
            let clock = ManualClock()
            let listener = try await LoopbackRedirectListener.start(clock: clock)
            let waiting = Task { try await listener.waitForCallback { $0.query?.contains("state=expected") == true } }
            let port = try #require(listener.redirectURI.port)
            await clock.waitForSleeper()  // the predicate is installed before the wait starts sleeping
            let refused = try await RawClient.send(
                "GET /callback?code=1&state=other HTTP/1.1\r\nHost: 127.0.0.1:\(port)\r\n\r\n", toPort: port)
            #expect(refused.hasPrefix("HTTP/1.1 400"))
            let target = try url(listener, "/callback?code=2&state=expected")
            _ = try await session.data(from: target)
            #expect(try await waiting.value == target)
        }

        @Test func closesAConnectionThatStaysSilent() async throws {
            let clock = ManualClock()
            let listener = try await LoopbackRedirectListener.start(clock: clock)
            defer { listener.cancel() }
            let port = try #require(listener.redirectURI.port)
            let waiting = Task { try await listener.waitForCallback() }
            defer { waiting.cancel() }
            async let reply = RawClient.send("", toPort: port)
            // The timeout of the wait and the deadline of the connection.
            try await clock.waitForSleepers(2)
            clock.advance(by: LoopbackConnection.timeout)
            #expect((try? await reply)?.isEmpty ?? true)
        }

        @Test func cancelClosesOpenConnections() async throws {
            let clock = ManualClock()
            let listener = try await LoopbackRedirectListener.start(clock: clock)
            let port = try #require(listener.redirectURI.port)
            let waiting = Task { try await listener.waitForCallback() }
            async let reply = RawClient.send("GET /callback", toPort: port)
            try await clock.waitForSleepers(2)
            listener.cancel()
            #expect((try? await reply)?.isEmpty ?? true)
            await #expect(throws: CancellationError.self) { try await waiting.value }
        }

        @Test func refusesConnectionsBeyondTheLimit() {
            let connections = LoopbackConnections()
            let opened = (0..<LoopbackConnections.maximum + 1).map { _ in
                NWConnection(host: .ipv4(.loopback), port: 9, using: .tcp)
            }
            #expect(opened.map { connections.admit($0) }.filter { $0 }.count == LoopbackConnections.maximum)
            connections.release(opened[0])
            #expect(connections.admit(opened[LoopbackConnections.maximum]))
            connections.closeAll()
            #expect(!connections.admit(opened[0]))
        }

        @Test func stopsWhenTheLastReferenceIsReleased() async throws {
            var listener: LoopbackRedirectListener? = try await LoopbackRedirectListener.start()
            let port = try #require(listener?.redirectURI.port)
            listener = nil
            // Closing is asynchronous: until it happens the listener still answers.
            let deadline = ContinuousClock.now.advanced(by: .seconds(10))
            while (try? await RawClient.send("GET / HTTP/1.1\r\n\r\n", toPort: port)).map(\.isEmpty) != nil {
                try #require(ContinuousClock.now < deadline, "The listener was still open.")
                try await Task.sleep(for: .milliseconds(10))
            }
        }

        @Test func rejectsAnInvalidPath() async {
            await #expect(throws: PassportError.self) { _ = try await LoopbackRedirectListener.start(path: "callback") }
            await #expect(throws: PassportError.self) { _ = try await LoopbackRedirectListener.start(path: "/a?b=c") }
        }
    }

    @Suite("Loopback user agent", .timeLimit(.minutes(1)))
    struct LoopbackUserAgentTests {
        @Test func opensTheURLAndReturnsTheRedirect() async throws {
            let listener = try await LoopbackRedirectListener.start()
            let redirect = try #require(URL(string: listener.redirectURI.absoluteString + "?code=abc&state=xyz"))
            let agent = LoopbackUserAgent(listener: listener) { opened in
                #expect(opened.host == "as.example.com")
                // The "browser" follows the authorization URL straight back to the redirect URI.
                _ = try await URLSession(configuration: .ephemeral).data(from: redirect)
            }
            let authorization = try #require(URL(string: "https://as.example.com/authorize"))
            #expect(try await agent.present(authorization, redirectURI: listener.redirectURI) == redirect)
        }

        @Test func refusesAForeignRedirectURI() async throws {
            let listener = try await LoopbackRedirectListener.start()
            let agent = LoopbackUserAgent(listener: listener) { _ in Issue.record("must not open the browser") }
            let authorization = try #require(URL(string: "https://as.example.com/authorize"))
            let foreign = try #require(URL(string: "http://127.0.0.1:1/callback"))
            await #expect(throws: PassportError(.invalidConfiguration)) {
                _ = try await agent.present(authorization, redirectURI: foreign)
            }
        }

        @Test func reportsABrowserThatCannotOpen() async throws {
            struct Failure: Error {}
            let listener = try await LoopbackRedirectListener.start()
            let agent = LoopbackUserAgent(listener: listener) { _ in throw Failure() }
            let authorization = try #require(URL(string: "https://as.example.com/authorize"))
            await #expect(throws: PassportError(.invalidConfiguration)) {
                _ = try await agent.present(authorization, redirectURI: listener.redirectURI)
            }
        }
    }

    extension ManualClock {
        /// Waits, in real time and without sleeping on this clock, until `count` tasks sleep on it.
        func waitForSleepers(_ count: Int) async throws {
            let deadline = ContinuousClock.now.advanced(by: .seconds(10))
            while sleeperCount < count {
                try #require(ContinuousClock.now < deadline, "Expected \(count) sleepers.")
                try await Task.sleep(for: .milliseconds(1))
            }
        }
    }

    /// A minimal TCP client that sends raw bytes, so tests can control the request exactly.
    private enum RawClient {
        static func send(_ request: String, toPort port: Int) async throws -> String {
            let connection = NWConnection(
                host: .ipv4(.loopback),
                port: try #require(NWEndpoint.Port(rawValue: UInt16(port))),
                using: .tcp
            )
            return try await withCheckedThrowingContinuation { continuation in
                let finished = Flag()
                @Sendable func finish(_ result: Result<String, any Error>) {
                    guard finished.setOnce() else { return }
                    connection.cancel()
                    continuation.resume(with: result)
                }
                connection.stateUpdateHandler = { state in
                    switch state {
                    case .ready:
                        connection.send(
                            content: Data(request.utf8),
                            completion: .contentProcessed { error in
                                if let error { finish(.failure(error)) }
                            }
                        )
                        readAll(connection, accumulated: Data(), finish: finish)
                    case .failed(let error), .waiting(let error):
                        finish(.failure(error))
                    default:
                        break
                    }
                }
                connection.start(queue: DispatchQueue(label: "passportkit.tests.raw-client"))
            }
        }

        private static func readAll(
            _ connection: NWConnection,
            accumulated: Data,
            finish: @escaping @Sendable (Result<String, any Error>) -> Void
        ) {
            connection.receive(minimumIncompleteLength: 1, maximumLength: 64 * 1024) { data, _, isComplete, error in
                let total = accumulated + (data ?? Data())
                if isComplete || error != nil {
                    // A reset after the reply still delivers what arrived before it.
                    if total.isEmpty, let error { return finish(.failure(error)) }
                    return finish(.success(String(decoding: total, as: UTF8.self)))
                }
                readAll(connection, accumulated: total, finish: finish)
            }
        }
    }

    private final class Flag: Sendable {
        private let value = NSLock()
        nonisolated(unsafe) private var set = false  // guarded by `value`
        func setOnce() -> Bool {
            value.withLock {
                defer { set = true }
                return !set
            }
        }
    }
#endif
