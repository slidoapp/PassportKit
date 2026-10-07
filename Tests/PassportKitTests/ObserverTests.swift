import Foundation
import Testing

@testable import PassportKit

@Suite(.timeLimit(.minutes(1)))
struct ObserverTests {
    @Test func requestAndResponseEventsUseTheInjectedClock() async throws {
        let observer = RecordingObserver()
        let clock = ManualClock()
        let transport = SlowTransport(clock: clock, delay: .seconds(2), response: .tokens())
        let client = try ClientFixtures.client(transport, clock: clock, observer: observer)
        async let result = client.clientCredentials()
        await clock.advanceToNextSleeper()
        _ = try await result
        #expect(
            observer.events == [
                .request(endpoint: .token, grantType: .clientCredentials),
                .response(endpoint: .token, statusCode: 200, errorCode: nil, duration: .seconds(2)),
            ])
    }

    @Test func errorResponsesCarryTheErrorCode() async throws {
        let observer = RecordingObserver()
        let transport = RecordingTransport([.oauthError("invalid_grant"), .json(200, "")])
        let client = try ClientFixtures.client(transport, observer: observer)
        _ = try? await client.refresh(refreshToken: Secret("rt"))
        try await client.revoke(Secret("rt"))
        let events = observer.events
        #expect(events.count == 4)
        guard case .response(.token, 400, "invalid_grant", _) = events[1] else {
            Issue.record("unexpected event \(events[1])")
            return
        }
        guard case .response(.revocation, 200, nil, _) = events[3] else {
            Issue.record("unexpected event \(events[3])")
            return
        }
    }

    @Test func eventsContainNoSecrets() async throws {
        let observer = RecordingObserver()
        let transport = RecordingTransport([
            .oauthError("invalid_grant"), .json(400, #"{"error":"sec ret \#(Canary.value)"}"#), .tokens(),
        ])
        let client = try ClientFixtures.client(
            transport, authentication: .clientSecretPost(clientID: "app", secret: Secret(Canary.value)),
            observer: observer)
        _ = try? await client.refresh(refreshToken: Secret(Canary.value), additionalParameters: ["k": Canary.value])
        _ = try? await client.clientCredentials()
        _ = try await client.requestToken(grantType: .tokenExchange, parameters: ["subject_token": Canary.value])
        let text = observer.events.map { "\($0)" }.joined()
        #expect(!text.isEmpty)
        #expect(!text.contains(Canary.value))
    }
}

/// Transport that takes `delay` on the injected clock before answering.
private struct SlowTransport: HTTPTransport {
    let clock: ManualClock
    let delay: Duration
    let response: RecordingTransport.Step

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        try await clock.sleep(for: delay)
        guard case .respond(let response) = response else { throw URLError(.badServerResponse) }
        return response
    }
}
