import Foundation

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Signs requests to a protected resource with a bearer token and decides what a failure means
/// (RFC 6750 §2.1, §3, §3.1).
///
/// A request is never sent without a token, and a rejected request is retried at most once. A 403, or a
/// challenge with `insufficient_scope`, never refreshes a token: a new token would not carry more scope.
public struct RequestAuthorizer: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    private let manager: TokenManager
    private let transport: any HTTPTransport

    /// Creates an authorizer that obtains tokens from `manager` and sends ``send(_:for:)`` requests on
    /// `transport`.
    public init(manager: TokenManager, transport: any HTTPTransport = URLSessionTransport()) {
        self.manager = manager
        self.transport = transport
    }

    /// A fixed summary: the injected transport is never reached, so a dump cannot show what it holds.
    public var description: String { "RequestAuthorizer()" }

    /// Same as ``description``.
    public var debugDescription: String { description }

    /// A mirror exposing the summary only.
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }

    /// Adds `Authorization: Bearer <token>` (RFC 6750 §2.1) and returns the token that was used.
    ///
    /// Throws what ``TokenManager/accessToken(for:)`` throws when no token can be obtained, and
    /// ``PassportError/Code-swift.struct/invalidConfiguration`` when the URL is neither `https` nor
    /// `http` on a loopback host, so a token never travels in clear text, or when the token's
    /// ``AccessToken/tokenType`` is not `Bearer` (compared case-insensitively): other types, such as
    /// sender-constrained `DPoP` tokens, need proof this authorizer cannot produce. Never returns an
    /// unsigned request.
    public func sign(
        _ request: URLRequest,
        for target: TokenTarget = .default
    ) async throws -> (URLRequest, AccessToken) {
        try Self.requireSecureTransport(request.url)
        let token = try await manager.accessToken(for: target)
        try Self.requireBearer(token)
        var signed = request
        signed.setValue("Bearer \(token.value.reveal())", forHTTPHeaderField: "Authorization")
        return (signed, token)
    }

    /// Adds `Authorization: Bearer <token>` (RFC 6750 §2.1) and returns the token that was used.
    ///
    /// Same rules as the `URLRequest` overload.
    public func sign(
        _ request: HTTPRequest,
        for target: TokenTarget = .default
    ) async throws -> (HTTPRequest, AccessToken) {
        try Self.requireSecureTransport(request.url)
        let token = try await manager.accessToken(for: target)
        try Self.requireBearer(token)
        var signed = request
        signed.headers["Authorization"] = "Bearer \(token.value.reveal())"
        return (signed, token)
    }

    /// Decides what to do with a response to a request sent with `token` (RFC 6750 §3.1).
    ///
    /// - A 401 with `error="insufficient_scope"` fails with ``PassportError/Code-swift.struct/insufficientScope``.
    /// - A 401 with `error="invalid_token"` or without a Bearer error code, at `attempt` 0, invalidates
    ///   `token` and answers ``RetryDecision/retry``. Only that exact token is dropped, so concurrent
    ///   requests that were rejected with it cause one refresh.
    /// - Any other 401 at `attempt` 1 or more fails with ``PassportError/Code-swift.struct/unauthorized``.
    /// - Everything else, including every 403, is delivered.
    public func evaluate(
        statusCode: Int,
        headers: HTTPHeaders,
        token: AccessToken,
        attempt: Int
    ) async -> RetryDecision {
        guard statusCode == 401 else { return .deliver }
        let challenge = AuthenticationChallenge.parse(headers.values(for: "WWW-Authenticate"))
            .first { $0.scheme == "bearer" && $0.parameters["error"] != nil }
        let code = challenge?.parameters["error"]
        if code == PassportError.Code.insufficientScope.rawValue {
            return .fail(
                PassportError(
                    .insufficientScope, statusCode: statusCode,
                    detail: challenge?.parameters["error_description"]
                ).redacting([token.value.reveal()]))
        }
        guard attempt == 0 else {
            return .fail(PassportError(.unauthorized, recovery: .resourceDenied, statusCode: statusCode))
        }
        guard code == nil || code == PassportError.Code.invalidToken.rawValue else { return .deliver }
        await manager.invalidate(token)
        return .retry
    }

    /// Signs, sends on the transport given at creation, evaluates and, after a rejected token, retries once with a fresh one.
    ///
    /// Returns the response for every status the decision table delivers, including 403.
    public func send(
        _ request: HTTPRequest,
        for target: TokenTarget = .default
    ) async throws -> HTTPResponse {
        var attempt = 0
        while true {
            let (signed, token) = try await sign(request, for: target)
            let response = try await transport.send(signed)
            switch await evaluate(
                statusCode: response.statusCode, headers: response.headers, token: token, attempt: attempt)
            {
            case .deliver: return response
            case .retry: attempt += 1
            case .fail(let error): throw error
            }
        }
    }

    /// Like ``send(_:for:)`` for `URLSession`, with the session supplied by the caller: the library
    /// never reaches for `URLSession.shared`.
    ///
    /// A transport failure is reported as ``PassportError/Code-swift.struct/transportFailure``; cancellation
    /// propagates unchanged.
    public func data(
        for request: URLRequest,
        target: TokenTarget = .default,
        session: URLSession
    ) async throws -> (Data, HTTPURLResponse) {
        var attempt = 0
        while true {
            let (signed, token) = try await sign(request, for: target)
            let data: Data
            let response: URLResponse
            do {
                (data, response) = try await session.data(for: signed)
            } catch let error as CancellationError {
                throw error
            } catch {
                throw PassportError(.transportFailure, underlying: error)
            }
            guard let http = response as? HTTPURLResponse else {
                throw PassportError(.invalidResponse, detail: "The response was not an HTTP response.")
            }
            var headers = HTTPHeaders()
            for (name, value) in http.allHeaderFields {
                if let name = name as? String, let value = value as? String { headers.append(name, value) }
            }
            switch await evaluate(statusCode: http.statusCode, headers: headers, token: token, attempt: attempt) {
            case .deliver: return (data, http)
            case .retry: attempt += 1
            case .fail(let error): throw error
            }
        }
    }

    private static func requireBearer(_ token: AccessToken) throws {
        guard token.tokenType.lowercased() == "bearer" else {
            throw PassportError(
                .invalidConfiguration,
                detail: "Only Bearer tokens can be sent; the server issued another type.")
        }
    }

    private static func requireSecureTransport(_ url: URL?) throws {
        let scheme = url?.scheme?.lowercased()
        guard scheme == "https" || (scheme == "http" && LoopbackHost.isLoopback(url?.host)) else {
            throw PassportError(
                .invalidConfiguration, detail: "Bearer tokens are only sent over https or to loopback.")
        }
    }
}
