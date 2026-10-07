import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("Testing module: clocks, seams, recording and override hooks")
struct SeamsAndHooksTests {
    @Test("ManualClock wakes sleepers in deadline order and never sleeps for real")
    func manualClockOrder() async throws {
        let clock = ManualClock()
        let order = Order()
        let long = Task {
            try await clock.sleep(for: .seconds(30))
            await order.append("long")
        }
        await clock.waitForSleeper()
        let short = Task {
            try await clock.sleep(for: .seconds(10))
            await order.append("short")
        }
        while clock.sleeperCount < 2 { await Task.yield() }

        #expect(await clock.advanceToNextSleeper() == .seconds(10))
        try await short.value
        #expect(await order.values == ["short"])
        clock.advance(by: .seconds(20))
        try await long.value
        #expect(await order.values == ["short", "long"])
        #expect(clock.now.offset == .seconds(30))
    }

    @Test("ManualClock sleep honours cancellation and ignores negative advances")
    func manualClockCancellation() async throws {
        let clock = ManualClock()
        let sleeper = Task { try await clock.sleep(for: .seconds(5)) }
        await clock.waitForSleeper()
        clock.advance(by: .seconds(-10))
        #expect(clock.now.offset == .zero)
        sleeper.cancel()
        await #expect(throws: CancellationError.self) { try await sleeper.value }
        #expect(clock.sleeperCount == 0)

        let cancelledBeforeStart = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            try await clock.sleep(for: .seconds(5))
        }
        await #expect(throws: CancellationError.self) { try await cancelledBeforeStart.value }
        try await clock.sleep(for: .zero)
    }

    @Test("FixedWallClock moves only when told to; SequenceRandomSource is deterministic")
    func seams() {
        let wall = FixedWallClock(Date(timeIntervalSince1970: 100))
        #expect(wall.now() == wall.now())
        wall.advance(by: .milliseconds(1500))
        #expect(wall.now() == Date(timeIntervalSince1970: 101.5))
        wall.set(Date(timeIntervalSince1970: 7))
        #expect(wall.now() == Date(timeIntervalSince1970: 7))

        let random = SequenceRandomSource([1, 2, 3])
        #expect(random.bytes(count: 5) == [1, 2, 3, 1, 2])
        #expect(random.bytes(count: 2) == [3, 1])
        #expect(SequenceRandomSource().bytes(count: 3) == [0, 1, 2])
    }

    @Test("RecordingTransport plays its script and decodes form parameters")
    func recordingTransport() async throws {
        let transport = RecordingTransport([.tokens("a"), .oauthError("invalid_grant")])
        let body = FormEncoding.encode([("grant_type", "refresh_token"), ("resource", "a b"), ("resource", "c+d")])
        let request = HTTPRequest(method: .post, url: URL(string: "https://as.example.com/token")!, body: body)
        #expect(try await transport.send(request).statusCode == 200)
        #expect(try await transport.send(request).statusCode == 400)
        await #expect(throws: RecordingTransport.ScriptExhausted.self) { try await transport.send(request) }
        await transport.enqueue(.json(201, "{}"))
        #expect(try await transport.send(request).statusCode == 201)

        let recorded = try #require(await transport.requests.first)
        #expect(recorded.value("grant_type") == "refresh_token")
        #expect(recorded.values("resource") == ["a b", "c+d"])
        #expect(recorded.formNames == ["grant_type", "resource", "resource"])
        #expect(await transport.requests.count == 4)
    }

    @Test("the override hook replaces answers, fails requests and delays on the injected clock")
    func overrides() async throws {
        let clock = ManualClock()
        let server = FakeAuthorizationServer(clients: [.app()], clock: clock)
        let url = FakeAuthorizationServer.tokenEndpoint
        let request = HTTPRequest(method: .post, url: url, body: FormEncoding.encode([("grant_type", "refresh_token")]))
        await server.configure {
            $0.override = { recorded in
                switch recorded.value("grant_type") {
                case "refresh_token":
                    .init(status: 503, body: "busy", headers: ["Retry-After": "7"], delay: .seconds(2))
                default: .init(failure: URLError(.notConnectedToInternet))
                }
            }
        }
        let pending = Task { try await server.send(request) }
        await clock.advanceToNextSleeper()
        let response = try await pending.value
        #expect(response.statusCode == 503)
        #expect(response.headers["Retry-After"] == "7")
        #expect(String(data: response.body, encoding: .utf8) == "busy")

        let other = HTTPRequest(method: .post, url: url, body: FormEncoding.encode([("grant_type", "password")]))
        await #expect(throws: URLError.self) { try await server.send(other) }
        #expect(await server.requestCount(for: .refreshToken) == 1)
        #expect(await server.requests(to: "/token").count == 2)
    }

    @Test("unknown hosts and paths fail like a network would")
    func routing() async throws {
        let fixture = Fixture()
        await #expect(throws: URLError.self) { try await fixture.get(URL(string: "https://elsewhere.example.com/")!) }
        #expect(try await fixture.get(URL(string: "https://as.example.com/nope")!).statusCode == 404)
        #expect(try await fixture.get(FakeAuthorizationServer.tokenEndpoint).statusCode == 405)
    }
}

actor Order {
    private(set) var values: [String] = []
    func append(_ value: String) { values.append(value) }
}
