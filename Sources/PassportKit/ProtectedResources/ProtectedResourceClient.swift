import Foundation
import HTTPTypes
import HTTPTypesFoundation
import Logging

/// Sends requests to a protected resource (RFC 6749 §1.1) with a bearer token and decides what a failure means
/// (RFC 6750 §2.1, §3, §3.1).
///
/// A request is never sent without a token, and a rejected request is retried at most once. A 403, or a
/// challenge with `insufficient_scope`, never refreshes a token: a new token would not carry more scope.
///
/// A bearer token is sent to whatever host the request names. When requests are built from URLs that a server
/// or a user can influence (links in a response, a redirect target stored earlier), pass `allowedOrigins`.
public struct ProtectedResourceClient: Sendable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    private let session: OAuthSession
    private let transport: any HTTPTransport
    private let allowedOrigins: Set<OriginKey>?

    /// Creates a client that obtains tokens from `session` and sends ``send(_:body:for:)`` requests on
    /// `transport`.
    ///
    /// - Parameters:
    ///   - session: Supplies the access tokens.
    ///   - transport: Sends the requests of ``send(_:body:for:)``.
    ///   - allowedOrigins: When not `nil`, the only origins a request may name. An origin is a URL whose
    ///     scheme, host and port count and whose path is ignored, such as `https://api.example.com`; a default
    ///     port equals an explicit one. Any other request fails with
    ///     ``PassportError/Code-swift.struct/invalidConfiguration`` before a token is obtained. An entry
    ///     without a scheme and host allows nothing.
    public init(
        session: OAuthSession,
        transport: any HTTPTransport = URLSessionTransport(),
        allowedOrigins: Set<URL>? = nil
    ) {
        self.session = session
        self.transport = transport
        self.allowedOrigins = allowedOrigins.map { Set($0.map(OriginKey.init)) }
    }

    /// A fixed summary: the injected transport is never reached, so a dump cannot show what it holds.
    public var description: String { "ProtectedResourceClient()" }

    /// Same as ``description``.
    public var debugDescription: String { description }

    /// A mirror exposing the summary only.
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }

    /// Returns `request` with `Authorization: Bearer <token>` added (RFC 6750 §2.1), and the token that was used.
    ///
    /// Throws what ``OAuthSession/accessToken(for:)`` throws when no token can be obtained,
    /// ``PassportError/Code-swift.struct/invalidResponse`` when the token is not a valid `b64token`
    /// (RFC 6750 §2.1), and ``PassportError/Code-swift.struct/invalidConfiguration`` when the URL is neither
    /// `https` (nor `http` on a loopback host, only when the session's client sets
    /// ``OAuthClient/Configuration/allowsInsecureLoopbackEndpoints``), so a token never travels in clear text, when its
    /// origin is not in `allowedOrigins`, or when the token's
    /// ``AccessToken/tokenType`` is not `Bearer` (compared case-insensitively): other types, such as
    /// sender-constrained `DPoP` tokens, need proof this client cannot produce. Never returns a
    /// request without the token.
    public func addingToken(
        to request: URLRequest,
        for target: TokenTarget = .default
    ) async throws -> (URLRequest, AccessToken) {
        try requireDestination(request.url)
        let token = try await session.accessToken(for: target)
        try Self.requireBearer(token)
        var prepared = request
        prepared.setValue(
            "\(AuthenticationScheme.bearer) \(token.value.reveal())",
            forHTTPHeaderField: HTTPField.Name.authorization.rawName)
        return (prepared, token)
    }

    /// Returns `request` with `Authorization: Bearer <token>` added (RFC 6750 §2.1), and the token that was used.
    ///
    /// Same rules as the `URLRequest` overload. The `Authorization` field is marked never indexed (RFC 7541
    /// §7.1.3). The marking reaches the wire only if the code that sends the request keeps the `indexingStrategy`
    /// of `HTTPFields`; converting to `URLRequest`, as ``URLSessionTransport`` does, drops it.
    ///
    /// The returned request is your value: `HTTPTypes.HTTPRequest` prints its method, URL with query and, under
    /// `dump`, every header field including `Authorization`. Never log a request that carries a token.
    public func addingToken(
        to request: HTTPRequest,
        for target: TokenTarget = .default
    ) async throws -> (HTTPRequest, AccessToken) {
        try requireDestination(request.url)
        let token = try await session.accessToken(for: target)
        try Self.requireBearer(token)
        var prepared = request
        prepared.headerFields.setSensitive(.authorization, "\(AuthenticationScheme.bearer) \(token.value.reveal())")
        return (prepared, token)
    }

    /// Handles a response to a request sent with `token` (RFC 6750 §3.1): it discards `token` from the session
    /// when the request should be retried, and returns what the caller does next.
    ///
    /// The discard (``OAuthSession/discard(_:)``) changes session state, so the next `addingToken(to:for:)` for
    /// the target obtains a new token. Pass `attempt` 0 for the response to the first request and 1 for the
    /// response to the retry. ``send(_:body:for:)`` and ``data(for:target:urlSession:)`` call this method for
    /// you.
    ///
    /// - A 401 with `error="insufficient_scope"` fails with ``PassportError/Code-swift.struct/insufficientScope``.
    /// - A 401 with `error="invalid_token"` or without a Bearer error code, at `attempt` 0, discards
    ///   `token` and answers ``RetryDecision/retry``. Only that exact token is dropped, so concurrent
    ///   requests that were rejected with it cause one refresh.
    /// - A 401 whose challenges are all for another scheme (`Basic`, `DPoP`) is delivered at `attempt` 0: a
    ///   new bearer token would not change the answer. A 401 without any challenge is treated like one with a
    ///   bare Bearer challenge, which is library policy: RFC 6750 §3.1 does not describe it.
    /// - Any other 401 at `attempt` 1 or more fails with ``PassportError/Code-swift.struct/unauthorized``.
    /// - Everything else, including every 403, is delivered.
    public func handleResponse(
        statusCode: Int,
        headers: HTTPFields,
        token: AccessToken,
        attempt: Int
    ) async -> RetryDecision {
        guard statusCode == 401 else { return .deliver }
        let challenges = AuthenticationChallenge.parse(headers[values: .wwwAuthenticate])
        let challenge = challenges.first {
            AuthenticationScheme.isBearer($0.scheme) && $0.parameters[ErrorResponseField.error] != nil
        }
        let code = challenge?.parameters[ErrorResponseField.error]
        if code == PassportError.Code.insufficientScope.rawValue {
            session.client.logger.notice("The resource answered insufficient_scope")
            return .fail(
                PassportError(
                    .insufficientScope, statusCode: statusCode,
                    detail: challenge?.parameters[ErrorResponseField.errorDescription]
                ).redacting([token.value.reveal()]))
        }
        guard attempt == 0 else {
            session.client.logger.notice("The resource rejected a renewed access token")
            return .fail(PassportError(.unauthorized, recovery: .resourceDenied, statusCode: statusCode))
        }
        if !challenges.isEmpty, !challenges.contains(where: { AuthenticationScheme.isBearer($0.scheme) }) {
            return .deliver
        }
        guard code == nil || code == PassportError.Code.invalidToken.rawValue else { return .deliver }
        session.client.logger.notice("The resource answered 401; retrying once with a new access token")
        await session.discard(token)
        return .retry
    }

    /// Adds the token, sends on the transport given at creation, handles the response with
    /// ``handleResponse(statusCode:headers:token:attempt:)`` and, after a rejected token, retries once with a new
    /// one.
    ///
    /// Returns the response and its body for every status the decision table delivers, including 403.
    public func send(
        _ request: HTTPRequest,
        body: Data? = nil,
        for target: TokenTarget = .default
    ) async throws -> (HTTPResponse, Data) {
        var attempt = 0
        while true {
            let (prepared, token) = try await addingToken(to: request, for: target)
            let (response, responseBody) = try await transport.send(prepared, body: body)
            switch await handleResponse(
                statusCode: response.status.code, headers: response.headerFields, token: token, attempt: attempt)
            {
            case .deliver: return (response, responseBody)
            case .retry: attempt += 1
            case .fail(let error): throw error
            }
        }
    }

    /// Like ``send(_:body:for:)`` for `URLSession`, with the URL session supplied by the caller: the library
    /// never reaches for `URLSession.shared`.
    ///
    /// Redirects follow the same rules as ``URLSessionTransport``: never from HTTPS to HTTP, and a redirect to
    /// another scheme, host or port drops every header but `Accept`, `Accept-Language` and `User-Agent`, so the
    /// token does not follow. This holds whatever the URL session's own delegate does.
    ///
    /// A transport failure is reported as ``PassportError/Code-swift.struct/transportFailure``; cancellation
    /// propagates unchanged.
    public func data(
        for request: URLRequest,
        target: TokenTarget = .default,
        urlSession: URLSession
    ) async throws -> (Data, HTTPURLResponse) {
        var attempt = 0
        while true {
            let (prepared, token) = try await addingToken(to: request, for: target)
            let data: Data
            let response: URLResponse
            do {
                (data, response) = try await urlSession.data(for: prepared, delegate: RedirectPolicyDelegate())
            } catch let error as CancellationError {
                throw error
            } catch {
                throw PassportError(.transportFailure, underlying: error)
            }
            guard let http = response as? HTTPURLResponse else {
                throw PassportError(.invalidResponse, detail: "The response was not an HTTP response.")
            }
            let headers = http.httpResponse?.headerFields ?? [:]
            switch await handleResponse(statusCode: http.statusCode, headers: headers, token: token, attempt: attempt)
            {
            case .deliver: return (data, http)
            case .retry: attempt += 1
            case .fail(let error): throw error
            }
        }
    }

    private static func requireBearer(_ token: AccessToken) throws {
        guard AuthenticationScheme.isBearer(token.tokenType) else {
            throw PassportError(
                .invalidConfiguration,
                detail: "Only Bearer tokens can be sent; the server issued another type.")
        }
        // RFC 6750 §2.1: b64token = 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"=". Anything else,
        // such as a line break, could not be a credential and must not reach a header.
        let value = Array(token.value.reveal().utf8)
        let body = value.prefix { $0 != UInt8(ascii: "=") }
        guard !body.isEmpty, value.dropFirst(body.count).allSatisfy({ $0 == UInt8(ascii: "=") }),
            body.allSatisfy({ isTokenCharacter($0) })
        else {
            throw PassportError(.invalidResponse, detail: "The access token is not a valid bearer token.")
        }
    }

    private static func isTokenCharacter(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"),
            UInt8(ascii: "0")...UInt8(ascii: "9"):
            return true
        default:
            return "-._~+/".utf8.contains(byte)
        }
    }

    private func requireDestination(_ url: URL?) throws {
        let scheme = url?.scheme?.lowercased()
        let allowsLoopback = session.client.configuration.allowsInsecureLoopbackEndpoints
        guard scheme == "https" || (scheme == "http" && allowsLoopback && LoopbackHost.isLoopback(url?.host)) else {
            throw PassportError(
                .invalidConfiguration,
                detail: allowsLoopback
                    ? "Bearer tokens are only sent over https or to loopback."
                    : "Bearer tokens are only sent over https. \(Endpoints.optInHint)"
            )
        }
        if let allowedOrigins, let url, !allowedOrigins.contains(OriginKey(url)) {
            throw PassportError(.invalidConfiguration, detail: "The request URL is not an allowed origin.")
        }
    }
}
