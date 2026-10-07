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
        context: ErrorResponseContext
    ) -> PassportError {
        let retryAfter = retryAfter(in: headers)
        guard case .object(let members)? = try? JSONDecoder().decode(JSONValue.self, from: body),
            case .string(let code)? = members["error"], !code.isEmpty
        else {
            let isTransient = statusCode == 429 || (500...599).contains(statusCode)
            let code: Code = isTransient ? .temporarilyUnavailable : .invalidResponse
            return PassportError(
                code,
                recovery: recovery(for: code, context: context, statusCode: statusCode, retryAfter: retryAfter),
                statusCode: statusCode,
                errorDescription: "The server response was not an OAuth error."
            )
        }
        var description: String?
        if case .string(let text)? = members["error_description"] { description = text }
        var uri: URL?
        if case .string(let text)? = members["error_uri"], let parsed = URL(string: text), parsed.scheme != nil {
            uri = parsed
        }
        return fromServerError(
            code: Code(rawValue: code),
            errorDescription: description,
            errorURI: uri,
            statusCode: statusCode,
            retryAfter: retryAfter,
            context: context
        )
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

    /// Parses `Retry-After` given as delta-seconds (RFC 9110 §10.2.3). HTTP-date values are ignored.
    static func retryAfter(in headers: HTTPHeaders) -> Duration? {
        guard let text = headers["Retry-After"]?.trimmingCharacters(in: .whitespaces),
            !text.isEmpty, text.allSatisfy(\.isASCII), text.allSatisfy(\.isNumber),
            let seconds = Int(text)
        else { return nil }
        return .seconds(seconds)
    }
}
