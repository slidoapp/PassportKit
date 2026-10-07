import Foundation

/// Stateless OAuth 2.0 protocol operations against one authorization server (specification §8).
///
/// The client keeps no tokens. Every operation sends one request (device polling sends several) and returns
/// the parsed result or throws ``PassportError``; cancellation propagates as `CancellationError`.
public struct OAuthClient: Sendable {
    let configuration: ClientConfiguration
    let transport: any HTTPTransport
    let wallClock: any WallClock
    let clock: any Clock<Duration>
    let random: any RandomSource
    let observer: (any PassportObserver)?

    /// Creates a client.
    ///
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/invalidConfiguration`` when the
    /// configuration fails ``ClientConfiguration/validate()``, so a misconfigured client never exists.
    public init(
        configuration: ClientConfiguration,
        transport: any HTTPTransport = URLSessionTransport(),
        wallClock: any WallClock = SystemWallClock(),
        clock: any Clock<Duration> = ContinuousClock(),
        random: any RandomSource = SystemRandomSource(),
        observer: (any PassportObserver)? = nil
    ) throws {
        try configuration.validate()
        self.configuration = configuration
        self.transport = transport
        self.wallClock = wallClock
        self.clock = clock
        self.random = random
        self.observer = observer
    }

    /// Sends a request, emitting observer events, and returns any HTTP response.
    ///
    /// Transport failures become ``PassportError/Code-swift.struct/transportFailure`` and are reported to the
    /// observer as ``PassportEvent/transportFailure(endpoint:grantType:duration:)``; `CancellationError`
    /// propagates unchanged, also when the transport reports cancellation as another error.
    func send(_ request: FormRequest) async throws -> HTTPResponse {
        let httpRequest = try request.build(configuration: configuration)
        observer?.record(.request(endpoint: request.endpoint, grantType: request.grantType))
        let stopwatch = Stopwatch(clock: clock)
        let response: HTTPResponse
        do {
            response = try await transport.send(httpRequest)
        } catch {
            observer?.record(
                .transportFailure(endpoint: request.endpoint, grantType: request.grantType, duration: stopwatch.elapsed)
            )
            if error is CancellationError || Task.isCancelled { throw CancellationError() }
            throw PassportError(
                .transportFailure,
                errorDescription: "The request to the authorization server failed.",
                underlying: error
            )
        }
        observer?.record(
            .response(
                endpoint: request.endpoint,
                statusCode: response.statusCode,
                errorCode: Self.errorCode(in: response),
                duration: stopwatch.elapsed
            )
        )
        return response
    }

    /// The OAuth `error` member of a non-2xx response, only when it is a short plain token.
    private static func errorCode(in response: HTTPResponse) -> String? {
        guard !(200..<300).contains(response.statusCode),
            case .object(let members)? = try? JSONDecoder().decode(JSONValue.self, from: response.body),
            case .string(let code)? = members["error"],
            (1...64).contains(code.count),
            code.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == ".") })
        else { return nil }
        return code
    }

    /// Sends a token endpoint request and parses the result.
    ///
    /// Non-2xx responses become errors classified by their body for `context` (specification §6).
    func performTokenRequest(
        _ request: FormRequest,
        context: ErrorResponseContext,
        exchange: Bool = false
    ) async throws -> TokenResponse {
        let response = try await send(request)
        guard (200..<300).contains(response.statusCode) else {
            throw PassportError.fromErrorResponse(
                statusCode: response.statusCode,
                headers: response.headers,
                body: response.body,
                context: context
            )
        }
        return try TokenResponse(parsing: response.body, exchange: exchange)
    }

    /// The URL of an optional endpoint, or an `invalidConfiguration` error naming it.
    func requireEndpoint(_ url: URL?, name: String) throws -> URL {
        guard let url else {
            throw PassportError(.invalidConfiguration, errorDescription: "The \(name) endpoint is not configured.")
        }
        return url
    }
}
