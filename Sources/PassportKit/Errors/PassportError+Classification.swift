import Foundation
import HTTPTypes

extension PassportError {
    /// Builds the error for a non-2xx authorization server response (specification §6, rules 1 and 2).
    ///
    /// The JSON `error` member decides the code (RFC 6749 §5.2); the status is only recorded. A body that is
    /// not a JSON object with a string `error` maps by status: 429 and 5xx to ``Code-swift.struct/temporarilyUnavailable``
    /// with ``Recovery-swift.enum/retryLater(after:)``, anything else to ``Code-swift.struct/invalidResponse``.
    static func fromErrorResponse(
        statusCode: Int,
        headers: HTTPFields,
        body: Data,
        context: ErrorResponseContext,
        now: Date? = nil
    ) -> PassportError {
        let retryAfter = retryAfter(in: headers, now: now)
        guard case .object(let members)? = try? JSONDecoder().decode(JSONValue.self, from: body),
            case .string(let text)? = members[ErrorResponseField.error], let code = Code.fromServer(text)
        else {
            let isTransient = HTTPResponse.Status.isTransient(code: statusCode)
            let code: Code = isTransient ? .temporarilyUnavailable : .invalidResponse
            return PassportError(
                code,
                recovery: recovery(for: code, context: context, statusCode: statusCode, retryAfter: retryAfter),
                statusCode: statusCode,
                detail: "The server response was not a well-formed OAuth error."
            )
        }
        var description: String?
        if case .string(let text)? = members[ErrorResponseField.errorDescription] { description = text }
        var uri: URL?
        if case .string(let text)? = members[ErrorResponseField.errorURI] { uri = Self.errorURI(from: text) }
        return fromServerError(
            code: code,
            detail: description,
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
        guard var text = detail else { return self }
        for secret in secrets where secret.count >= 4 {
            text = text.replacingOccurrences(of: secret, with: "<redacted>")
        }
        var copy = self
        copy.detail = text
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
        detail: String? = nil,
        errorURI: URL? = nil,
        statusCode: Int? = nil,
        retryAfter: Duration? = nil,
        context: ErrorResponseContext
    ) -> PassportError {
        PassportError(
            code,
            recovery: recovery(for: code, context: context, statusCode: statusCode, retryAfter: retryAfter),
            statusCode: statusCode,
            detail: detail,
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
            context == .refreshGrant || context == .exchangeWithRefreshToken ? .reauthenticate : .noAction
        case .accessDenied:
            context == .deviceAuthorizationPoll || context == .authorizationResponse ? .noAction : .resourceDenied
        case .invalidTarget, .insufficientScope, .tokenRejected:
            .resourceDenied
        case .invalidClient, .unauthorizedClient, .unsupportedGrantType, .invalidRequest, .invalidScope,
            .invalidConfiguration:
            .fixConfiguration
        case .temporarilyUnavailable, .serverError, .transportFailure:
            .retryLater(after: retryAfter)
        case .expiredToken:
            context == .deviceAuthorizationPoll ? .reauthenticate : .noAction
        default:
            statusCode.map(HTTPResponse.Status.isTransient(code:)) == true
                ? .retryLater(after: retryAfter) : .noAction
        }
    }

    /// Parses `Retry-After` (RFC 9110 §10.2.3): delta-seconds, or an HTTP-date relative to `now`. A date in the
    /// past means zero. Without `now`, HTTP-date values are ignored.
    static func retryAfter(in headers: HTTPFields, now: Date? = nil) -> Duration? {
        guard let text = headers[.retryAfter]?.trimmingCharacters(in: .whitespaces), !text.isEmpty,
            text.allSatisfy(\.isASCII)
        else { return nil }
        if text.allSatisfy(\.isNumber) { return Int(text).map { .seconds($0) } }
        guard let now, let date = parseHTTPDate(text, now: now) else { return nil }
        return .seconds(max(0, Int(min(date.timeIntervalSince(now), 31_536_000_000).rounded(.up))))
    }

    /// The preferred HTTP-date format (RFC 9110 §5.6.7), for example `Sun, 06 Nov 1994 08:49:37 GMT`.
    private static let imfFixdate = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
    /// The obsolete RFC 850 format (RFC 9110 §5.6.7), for example `Sunday, 06-Nov-94 08:49:37 GMT`.
    private static let rfc850Date = "EEEE, dd-MMM-yy HH:mm:ss 'GMT'"
    /// The obsolete ANSI C `asctime()` format (RFC 9110 §5.6.7), for example `Sun Nov  6 08:49:37 1994`.
    private static let asctimeDate = "EEE MMM d HH:mm:ss yyyy"

    /// Parses the three HTTP-date formats a recipient must accept (RFC 9110 §5.6.7).
    ///
    /// `Date.HTTPFormatStyle` is not used because it parses only IMF-fixdate, and a recipient must also accept the
    /// two obsolete formats. A two-digit RFC 850 year that would be more than 50 years after `now` is the most
    /// recent past year with those digits (§5.6.7), so two-digit years fall in the century from 50 years before
    /// `now`.
    private static func parseHTTPDate(_ text: String, now: Date) -> Date? {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "GMT") ?? calendar.timeZone
        for format in [imfFixdate, rfc850Date, asctimeDate] {
            let formatter = DateFormatter()
            formatter.locale = Locale(identifier: "en_US_POSIX")
            formatter.timeZone = TimeZone(identifier: "GMT")
            formatter.calendar = calendar
            formatter.twoDigitStartDate = calendar.date(byAdding: .year, value: -50, to: now)
            formatter.dateFormat = format
            if let date = formatter.date(from: text) { return date }
        }
        return nil
    }
}
