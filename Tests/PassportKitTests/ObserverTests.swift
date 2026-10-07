import Foundation
import PassportKitTesting
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

    @Test func discoveryReportsMetadataEvents() async throws {
        let observer = RecordingObserver()
        let issuer = URL(string: "https://as.example.com")!
        let ok = RecordingTransport([.json(200, #"{"issuer":"https://as.example.com"}"#)])
        _ = try await Discovery.fetchMetadata(issuer: issuer, transport: ok, observer: observer)
        let failing = RecordingTransport([.oauthError("invalid_request"), .fail(URLError(.timedOut))])
        _ = try? await Discovery.fetchMetadata(issuer: issuer, transport: failing, observer: observer)
        _ = try? await Discovery.fetchMetadata(issuer: issuer, transport: failing, observer: observer)
        let events = observer.events
        #expect(events.count == 6)
        #expect(events[0] == .request(endpoint: .metadata, grantType: nil))
        guard case .response(.metadata, 200, nil, _) = events[1],
            case .response(.metadata, 400, "invalid_request", _) = events[3],
            case .transportFailure(.metadata, nil, _) = events[5]
        else {
            Issue.record("unexpected events \(events)")
            return
        }
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

    @Test func transportFailureTerminatesTheRequest() async throws {
        let observer = RecordingObserver()
        let clock = ManualClock()
        let transport = SlowTransport(clock: clock, delay: .seconds(3), response: .fail(URLError(.timedOut)))
        let client = try ClientFixtures.client(transport, clock: clock, observer: observer)
        async let result: TokenResponse = client.clientCredentials()
        await clock.advanceToNextSleeper()
        do {
            _ = try await result
            Issue.record("expected a failure")
        } catch let error as PassportError {
            #expect(error.code == .transportFailure)
        }
        #expect(
            observer.events == [
                .request(endpoint: .token, grantType: .clientCredentials),
                .transportFailure(endpoint: .token, grantType: .clientCredentials, duration: .seconds(3)),
            ])
    }

    @Test func cancellationAlsoTerminatesTheRequest() async throws {
        let observer = RecordingObserver()
        let transport = RecordingTransport([.fail(CancellationError())])
        let client = try ClientFixtures.client(transport, observer: observer)
        await #expect(throws: CancellationError.self) { try await client.clientCredentials() }
        let events = observer.events
        #expect(events.count == 2)
        guard case .transportFailure(.token, .clientCredentials, _) = events[1] else {
            Issue.record("unexpected event \(events[1])")
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
        switch response {
        case .respond(let response): return response
        case .fail(let error): throw error
        }
    }
}
