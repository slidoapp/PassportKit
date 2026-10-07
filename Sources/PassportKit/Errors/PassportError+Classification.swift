import Foundation

extension PassportError {
    /// Builds the error for a non-2xx authorization server response (specification §6, rules 1 and 2).
    ///
    /// The JSON `error` member decides the code (RFC 6749 §5.2); the status is only recorded. A body that is
    /// not a JSON object with a string `error` maps by status: 429 and 5xx to ``Code-swift.struct/temporarilyUnavailable``
    /// with ``Recovery-swift.enum/retryLater(after:)``, anything else to ``Code-swift.struct/invalidResponse``.
    static func fromErrorResponse(
        statusCode: Int,
        headers: HTTPHeaders,
        body: Data,
        context: ErrorResponseContext,
        now: Date? = nil
    ) -> PassportError {
        let retryAfter = retryAfter(in: headers, now: now)
        guard case .object(let members)? = try? JSONDecoder().decode(JSONValue.self, from: body),
            case .string(let text)? = members["error"], let code = Code.fromServer(text)
        else {
            let isTransient = statusCode == 429 || (500...599).contains(statusCode)
            let code: Code = isTransient ? .temporarilyUnavailable : .invalidResponse
            return PassportError(
                code,
                recovery: recovery(for: code, context: context, statusCode: statusCode, retryAfter: retryAfter),
                statusCode: statusCode,
                errorDescription: "The server response was not a well-formed OAuth error."
            )
        }
        var description: String?
        if case .string(let text)? = members["error_description"] { description = text }
        var uri: URL?
        if case .string(let text)? = members["error_uri"] { uri = Self.errorURI(from: text) }
        return fromServerError(
            code: code,
            errorDescription: description,
            errorURI: uri,
            statusCode: statusCode,
            retryAfter: retryAfter,
            context: context
        )
    }

    /// Returns the error with every occurrence of `secrets` in its description replaced, however short.
    ///
    /// The description rule that redacts long token-like runs cannot recognise a short token; this is for the
    /// values the library itself sent, which a careless server may repeat in `error_description`. Values of fewer than
    /// four characters are left alone: they would also match ordinary words.
    func redacting(_ secrets: [String]) -> PassportError {
        guard var text = errorDescription else { return self }
        for secret in secrets where secret.count >= 4 {
            text = text.replacingOccurrences(of: secret, with: "<redacted>")
        }
        var copy = self
        copy.errorDescription = text
        return copy
    }

    /// Parses an `error_uri` (RFC 6749 §5.2). Only `http` and `https` are kept: the value is server-controlled
    /// and an application may open it.
    static func errorURI(from text: String) -> URL? {
        guard let url = URL(string: text), let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https",
            url.host?.isEmpty == false
        else { return nil }
        return url
    }

    /// Builds the error for an OAuth error code that was already extracted, for example from a redirect.
    static func fromServerError(
        code: Code,
        errorDescription: String? = nil,
        errorURI: URL? = nil,
        statusCode: Int? = nil,
        retryAfter: Duration? = nil,
        context: ErrorResponseContext
    ) -> PassportError {
        PassportError(
            code,
            recovery: recovery(for: code, context: context, statusCode: statusCode, retryAfter: retryAfter),
            statusCode: statusCode,
            errorDescription: errorDescription,
            errorURI: errorURI
        )
    }

    /// The recovery table of specification §6, rule 3. Unknown codes fall back to status: 429 and 5xx are
    /// retryable, anything else has no recovery.
    static func recovery(
        for code: Code,
        context: ErrorResponseContext,
        statusCode: Int?,
        retryAfter: Duration?
    ) -> Recovery {
        switch code {
        case .invalidGrant:
            context == .refreshGrant || context == .exchangeWithRefreshToken ? .reauthenticate : .none
        case .accessDenied:
            context == .deviceAuthorizationPoll || context == .authorizationResponse ? .none : .resourceDenied
        case .invalidTarget, .insufficientScope, .tokenRejected:
            .resourceDenied
        case .invalidClient, .unauthorizedClient, .unsupportedGrantType, .invalidRequest, .invalidScope,
            .invalidConfiguration:
            .fixConfiguration
        case .temporarilyUnavailable, .serverError, .transportFailure:
            .retryLater(after: retryAfter)
        case .expiredToken:
            context == .deviceAuthorizationPoll ? .reauthenticate : .none
        default:
            statusCode.map { $0 == 429 || (500...599).contains($0) } == true ? .retryLater(after: retryAfter) : .none
        }
    }

    /// Parses `Retry-After` (RFC 9110 §10.2.3): delta-seconds, or an HTTP-date relative to `now`. A date in the
    /// past means zero. Without `now`, HTTP-date values are ignored.
    static func retryAfter(in headers: HTTPHeaders, now: Date? = nil) -> Duration? {
        guard let text = headers["Retry-After"]?.trimmingCharacters(in: .whitespaces), !text.isEmpty,
            text.allSatisfy(\.isASCII)
        else { return nil }
        if text.allSatisfy(\.isNumber) { return Int(text).map { .seconds($0) } }
        guard let now, let date = parseHTTPDate(text) else { return nil }
        return .seconds(max(0, Int(min(date.timeIntervalSince(now), 31_536_000_000).rounded(.up))))
    }

    /// The three HTTP-date formats a recipient must accept (RFC 9110 §5.6.7).
    private static func parseHTTPDate(_ text: String) -> Date? {
        for format in [
            "EEE, dd MMM yyyy HH:mm:ss 'GMT'", "EEEE, dd-MMM-yy HH:mm:ss 'GMT'", "EEE MMM d HH:mm:ss yyyy",
        ] {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(identifier: "GMT")
            formatter.dateFormat = format
            if let date = formatter.date(from: text) { return date }
        }
        return nil
    }
}
