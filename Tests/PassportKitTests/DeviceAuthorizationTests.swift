import Foundation
import PassportKitTesting
import Testing

@testable import PassportKit

@Suite(.timeLimit(.minutes(1)))
struct DeviceAuthorizationTests {
    private static let deviceJSON =
        #"{"device_code":"dev-secret","user_code":"WDJB-MJHT","verification_uri":"https://as.example.com/device","#
        + #""verification_uri_complete":"https://as.example.com/device?user_code=WDJB-MJHT","expires_in":900,"interval":7}"#

    private func start(
        _ steps: [RecordingTransport.Step],
        clock: ManualClock = ManualClock()
    ) async throws -> (OAuthClient, RecordingTransport, ManualClock, DeviceAuthorization) {
        let transport = RecordingTransport([.json(200, Self.deviceJSON)] + steps)
        let client = try ClientFixtures.client(transport, clock: clock)
        let authorization = try await client.startDeviceAuthorization()
        return (client, transport, clock, authorization)
    }

    /// Runs polling to its end, answering exactly `sleeps` sleeps, and returns each wait with the final result.
    private func poll(
        _ client: OAuthClient,
        _ authorization: DeviceAuthorization,
        clock: ManualClock,
        sleeps: Int,
        additionalParameters: AdditionalParameters = [:]
    ) async -> (waits: [Duration], result: Result<TokenResponse, any Error>) {
        let task = Task {
            try await client.completeDeviceAuthorization(authorization, additionalParameters: additionalParameters)
        }
        var waits: [Duration] = []
        for _ in 0..<sleeps { waits.append(await clock.advanceToNextSleeper()) }
        return (waits, await task.result)
    }

    private func failure(_ result: Result<TokenResponse, any Error>) -> PassportError? {
        if case .failure(let error) = result { return error as? PassportError }
        return nil
    }

    // MARK: Start

    @Test func startSendsClientIDScopeAndResources() async throws {
        let transport = RecordingTransport([.json(200, Self.deviceJSON)])
        let client = try ClientFixtures.client(transport)
        _ = try await client.startDeviceAuthorization(
            scope: ["b", "a"], resources: [URL(string: "https://api.example.com")!], additionalParameters: ["k": "v"])
        let sent = try #require(await transport.requests.first)
        #expect(sent.request.url == ClientFixtures.deviceURL)
        #expect(sent.request.headers["Accept"] == "application/json")
        #expect(
            sent.form.map { "\($0.0)=\($0.1)" } == [
                "scope=a b", "resource=https://api.example.com", "client_id=app", "k=v",
            ])
    }

    @Test func startParsesAllMembers() async throws {
        let (_, _, _, authorization) = try await start([])
        #expect(authorization.userCode == "WDJB-MJHT")
        #expect(authorization.verificationURI.absoluteString == "https://as.example.com/device")
        #expect(
            authorization.verificationURIComplete?.absoluteString == "https://as.example.com/device?user_code=WDJB-MJHT"
        )
        #expect(authorization.expiresIn == .seconds(900))
        #expect(authorization.interval == .seconds(7))
        #expect(authorization.remainingLifetime == .seconds(900))
    }

    @Test func startAppliesDefaultsAliasAndStringNumbers() async throws {
        let body =
            #"{"device_code":"d","user_code":"u","verification_url":"https://as.example.com/v","expires_in":"120"}"#
        let client = try ClientFixtures.client(RecordingTransport([.json(200, body)]))
        let authorization = try await client.startDeviceAuthorization()
        #expect(authorization.verificationURI.absoluteString == "https://as.example.com/v")
        #expect(authorization.verificationURIComplete == nil)
        #expect(authorization.interval == .seconds(5))
        #expect(authorization.expiresIn == .seconds(120))
    }

    @Test(arguments: [
        #"{"user_code":"u","verification_uri":"https://as.example.com/v","expires_in":60}"#,
        #"{"device_code":"d","verification_uri":"https://as.example.com/v","expires_in":60}"#,
        #"{"device_code":"d","user_code":"u","expires_in":60}"#,
        #"{"device_code":"d","user_code":"u","verification_uri":"https://as.example.com/v"}"#,
        #"{"device_code":"d","user_code":"u","verification_uri":"https://as.example.com/v","expires_in":0}"#,
        "[]",
    ])
    func startRejectsIncompleteResponses(body: String) async throws {
        let client = try ClientFixtures.client(RecordingTransport([.json(200, body)]))
        let error = await #expect(throws: PassportError.self) { try await client.startDeviceAuthorization() }
        #expect(error?.code == .invalidResponse)
    }

    @Test func startWithoutEndpointIsInvalidConfiguration() async throws {
        let configuration = ClientConfiguration(
            endpoints: Endpoints(token: ClientFixtures.tokenURL), authentication: .none(clientID: "app"))
        let client = try OAuthClient(configuration: configuration, transport: RecordingTransport())
        let error = await #expect(throws: PassportError.self) { try await client.startDeviceAuthorization() }
        #expect(error?.code == .invalidConfiguration)
    }

    @Test func startMapsServerErrors() async throws {
        let client = try ClientFixtures.client(RecordingTransport([.oauthError("invalid_scope")]))
        let error = await #expect(throws: PassportError.self) { try await client.startDeviceAuthorization() }
        #expect(error?.code == .invalidScope)
        #expect(error?.recovery == .fixConfiguration)
    }

    @Test func descriptionsHideTheDeviceCode() async throws {
        let (_, _, _, authorization) = try await start([])
        for text in Canary.renderings(of: authorization) {
            #expect(!text.contains("dev-secret"))
        }
    }

    // MARK: Polling

    @Test func pendingThenSuccess() async throws {
        let (client, transport, clock, authorization) = try await start([
            .oauthError("authorization_pending"), .oauthError("authorization_pending"), .tokens("done"),
        ])
        let outcome = await poll(client, authorization, clock: clock, sleeps: 3)
        #expect(outcome.waits == [.seconds(7), .seconds(7), .seconds(7)])
        #expect(try outcome.result.get().accessToken.reveal() == "done")
        let polls = Array(await transport.requests.dropFirst())
        #expect(polls.count == 3)
        #expect(polls[0].request.url == ClientFixtures.tokenURL)
        #expect(
            polls[0].form.map { "\($0.0)=\($0.1)" }
                == [
                    "grant_type=urn:ietf:params:oauth:grant-type:device_code", "device_code=dev-secret",
                    "client_id=app",
                ])
    }

    @Test func additionalParametersAreAppendedToPolls() async throws {
        let (client, transport, clock, authorization) = try await start([.tokens()])
        let outcome = await poll(client, authorization, clock: clock, sleeps: 1, additionalParameters: ["k": "v"])
        _ = try outcome.result.get()
        #expect(try #require(await transport.requests.last).form.last.map { "\($0.0)=\($0.1)" } == "k=v")
    }

    @Test func collidingAdditionalParameterFailsBeforePolling() async throws {
        let (client, transport, clock, authorization) = try await start([.tokens()])
        let outcome = await poll(
            client, authorization, clock: clock, sleeps: 1, additionalParameters: ["device_code": "x"])
        #expect(failure(outcome.result)?.code == .invalidConfiguration)
        #expect(await transport.requests.count == 1)
    }

    @Test func slowDownIsCumulative() async throws {
        let (client, _, clock, authorization) = try await start([
            .oauthError("slow_down"), .oauthError("slow_down"), .oauthError("authorization_pending"), .tokens(),
        ])
        let outcome = await poll(client, authorization, clock: clock, sleeps: 4)
        #expect(outcome.waits == [.seconds(7), .seconds(12), .seconds(17), .seconds(17)])
        _ = try outcome.result.get()
    }

    @Test func backsOffOnTransportErrorsAndServerFailuresThenResets() async throws {
        let (client, _, clock, authorization) = try await start(
            [
                .fail(URLError(.timedOut)), .oauthError("x", status: 503), .json(500, "oops"),
                .oauthError("authorization_pending"), .fail(URLError(.timedOut)), .tokens(),
            ], clock: ManualClock())
        // Interval 7: waits double from the interval, cap at 30, reset after a server answer.
        let outcome = await poll(client, authorization, clock: clock, sleeps: 6)
        #expect(outcome.waits == [7, 14, 28, 30, 7, 14].map { .seconds($0) })
        _ = try outcome.result.get()
    }

    @Test func retryAfterLongerThanBackoffWins() async throws {
        let (client, _, clock, authorization) = try await start([
            .oauthError("temporarily_unavailable", status: 429, headers: ["Retry-After": "60"]),
            .json(503, "", headers: ["Retry-After": "1"]), .tokens(),
        ])
        let outcome = await poll(client, authorization, clock: clock, sleeps: 3)
        #expect(outcome.waits == [.seconds(7), .seconds(60), .seconds(28)])
        _ = try outcome.result.get()
    }

    @Test func expiresWithoutSendingAfterTheDeadline() async throws {
        let clock = ManualClock()
        let body = #"{"device_code":"d","user_code":"u","verification_uri":"https://as.example.com/v","expires_in":12}"#
        let transport = RecordingTransport([
            .json(200, body), .oauthError("authorization_pending"), .oauthError("authorization_pending"), .tokens(),
        ])
        let client = try ClientFixtures.client(transport, clock: clock)
        let authorization = try await client.startDeviceAuthorization()
        let outcome = await poll(client, authorization, clock: clock, sleeps: 3)
        #expect(outcome.waits == [.seconds(5), .seconds(5), .seconds(2)])
        let error = failure(outcome.result)
        #expect(error?.code == .expiredToken)
        #expect(error?.recovery == .reauthenticate)
        #expect(await transport.requests.count == 3)  // start + two polls, none at or after the deadline
        #expect(authorization.remainingLifetime == .zero)
    }

    @Test func alreadyExpiredAuthorizationSendsNothing() async throws {
        let (client, transport, clock, authorization) = try await start([.tokens()])
        clock.advance(by: .seconds(900))
        let outcome = await poll(client, authorization, clock: clock, sleeps: 0)
        #expect(failure(outcome.result)?.code == .expiredToken)
        #expect(await transport.requests.count == 1)
    }

    @Test func accessDeniedIsTerminalWithoutRecovery() async throws {
        let (client, transport, clock, authorization) = try await start([.oauthError("access_denied"), .tokens()])
        let outcome = await poll(client, authorization, clock: clock, sleeps: 1)
        let error = failure(outcome.result)
        #expect(error?.code == .accessDenied)
        #expect(error?.recovery == PassportError.Recovery.none)
        #expect(await transport.requests.count == 2)
    }

    @Test func expiredTokenIsTerminalAndNeedsReauthentication() async throws {
        let (client, transport, clock, authorization) = try await start([.oauthError("expired_token"), .tokens()])
        let outcome = await poll(client, authorization, clock: clock, sleeps: 1)
        let error = failure(outcome.result)
        #expect(error?.code == .expiredToken)
        #expect(error?.recovery == .reauthenticate)
        #expect(await transport.requests.count == 2)
    }

    @Test func otherClientErrorsAreTerminal() async throws {
        let (client, transport, clock, authorization) = try await start([
            .oauthError("invalid_client", status: 401), .tokens(),
        ])
        let outcome = await poll(client, authorization, clock: clock, sleeps: 1)
        #expect(failure(outcome.result)?.recovery == .fixConfiguration)
        #expect(await transport.requests.count == 2)
    }

    @Test func cancellationDuringSleepStopsImmediately() async throws {
        let (client, transport, clock, authorization) = try await start([.tokens()])
        let task = Task { try await client.completeDeviceAuthorization(authorization) }
        await clock.waitForSleeper()
        task.cancel()
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(await transport.requests.count == 1)
        #expect(clock.sleeperCount == 0)
    }

    @Test func cancelledBeforeStartingSendsNothing() async throws {
        let (client, transport, _, authorization) = try await start([.tokens()])
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await client.completeDeviceAuthorization(authorization)
        }
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(await transport.requests.count == 1)
    }

    @Test func pollingEventsCarryTheDeviceGrant() async throws {
        let observer = RecordingObserver()
        let clock = ManualClock()
        let transport = RecordingTransport([.json(200, Self.deviceJSON), .tokens()])
        let client = try ClientFixtures.client(transport, clock: clock, observer: observer)
        let authorization = try await client.startDeviceAuthorization()
        let outcome = await poll(client, authorization, clock: clock, sleeps: 1)
        _ = try outcome.result.get()
        let events = observer.events
        #expect(events[0] == .request(endpoint: .deviceAuthorization, grantType: nil))
        #expect(events[2] == .request(endpoint: .token, grantType: .deviceCode))
        #expect("\(events)".contains("dev-secret") == false)
    }
}
