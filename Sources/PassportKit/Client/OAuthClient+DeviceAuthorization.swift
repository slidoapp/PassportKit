import Foundation

extension OAuthClient {
    /// The longest wait between polls after transport errors, 429 and 5xx responses (RFC 8628 §3.5).
    private static let maximumBackoff = Duration.seconds(30)
    /// The permanent increase of the polling interval on `slow_down` (RFC 8628 §3.5).
    private static let slowDownIncrement = Duration.seconds(5)

    /// Starts the device authorization grant (RFC 8628 §3.1, §3.2).
    ///
    /// Show ``DeviceAuthorization/userCode`` and ``DeviceAuthorization/verificationURI`` to the user, then call
    /// ``completeDeviceAuthorization(_:additionalParameters:)``. The library never opens a browser.
    /// Throws `invalidConfiguration` when no device authorization endpoint is configured.
    public func startDeviceAuthorization(
        scope: ScopeSet? = nil,
        resources: [URL] = [],
        additionalParameters: AdditionalParameters = [:]
    ) async throws -> DeviceAuthorization {
        var request = FormRequest(
            endpoint: .deviceAuthorization,
            url: try requireEndpoint(configuration.endpoints.deviceAuthorization, name: "device authorization")
        )
        request.add(scope: scope)
        try request.add(resources: resources)
        request.additionalParameters = additionalParameters
        let response = try await send(request)
        guard (200..<300).contains(response.statusCode) else {
            throw PassportError.fromErrorResponse(
                statusCode: response.statusCode,
                headers: response.headers,
                body: response.body,
                context: .other
            )
        }
        return try DeviceAuthorization(parsing: response.body, wallClock: wallClock, clock: clock)
    }

    /// Polls the token endpoint until the user approves, declines or the authorization expires (RFC 8628 §3.4, §3.5).
    ///
    /// The client waits the interval before every request. `authorization_pending` continues; `slow_down` adds
    /// 5 seconds permanently; transport errors, 429 and 5xx back off exponentially from the interval up to 30
    /// seconds (a larger `Retry-After` wins) and the delay resets after the next server answer. No request is
    /// sent after the deadline: the call throws `expiredToken` with recovery `reauthenticate` instead.
    /// `access_denied` throws with recovery `none`; `expired_token` is terminal. Cancellation stops
    /// immediately with `CancellationError`.
    public func completeDeviceAuthorization(
        _ authorization: DeviceAuthorization,
        additionalParameters: AdditionalParameters = [:]
    ) async throws -> TokenResponse {
        let lifetime = authorization.remainingLifetime
        let stopwatch = Stopwatch(clock: clock)
        var interval = authorization.interval
        var backoff: Duration?
        var wait = interval
        while true {
            try Task.checkCancellation()
            let remaining = lifetime - stopwatch.elapsed
            let pause = min(wait, remaining)
            if pause > .zero { try await clock.sleep(for: pause) }
            guard lifetime - stopwatch.elapsed > .zero else {
                throw PassportError(
                    .expiredToken,
                    recovery: .reauthenticate,
                    errorDescription: "The device authorization expired before it was approved."
                )
            }

            var request = FormRequest(tokenEndpoint: configuration.endpoints.token, grantType: .deviceCode)
            request.add("device_code", authorization.deviceCode.reveal())
            request.additionalParameters = additionalParameters

            let response: HTTPResponse
            do {
                response = try await send(request)
            } catch let error as PassportError where error.code == .transportFailure {
                backoff = nextBackoff(after: backoff, interval: interval)
                wait = backoff ?? interval
                continue
            }
            if (200..<300).contains(response.statusCode) {
                return try TokenResponse(parsing: response.body)
            }
            let error = PassportError.fromErrorResponse(
                statusCode: response.statusCode,
                headers: response.headers,
                body: response.body,
                context: .deviceAuthorizationPoll
            )
            switch error.code {
            case .authorizationPending:
                backoff = nil
                wait = interval
            case .slowDown:
                interval += Self.slowDownIncrement
                backoff = nil
                wait = interval
            case .accessDenied, .expiredToken:
                throw error
            default:
                let isTransient: Bool
                if case .retryLater = error.recovery {
                    isTransient = true
                } else {
                    isTransient = response.statusCode == 429 || (500...599).contains(response.statusCode)
                }
                guard isTransient else { throw error }
                backoff = nextBackoff(after: backoff, interval: interval)
                wait = max(backoff ?? interval, PassportError.retryAfter(in: response.headers) ?? .zero)
            }
        }
    }

    /// Doubles the previous backoff (or the interval), capped at 30 seconds but never below the interval.
    private func nextBackoff(after previous: Duration?, interval: Duration) -> Duration {
        max(interval, min((previous ?? interval) * 2, Self.maximumBackoff))
    }
}
