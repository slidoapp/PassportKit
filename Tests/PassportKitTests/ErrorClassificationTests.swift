import Foundation
import Testing

@testable import PassportKit

struct ErrorClassificationTests {
    typealias Code = PassportError.Code

    static let serverCodes: [Code] = [
        .invalidRequest, .invalidClient, .invalidGrant, .unauthorizedClient, .unsupportedGrantType, .invalidScope,
        .invalidTarget, .accessDenied, .expiredToken, .authorizationPending, .slowDown, .temporarilyUnavailable,
        .serverError, .invalidToken, .insufficientScope,
    ]
    static let clientCodes: [Code] = [
        .invalidResponse, .invalidConfiguration, .stateMismatch, .issuerMismatch, .transportFailure, .storageFailure,
        .tokenRejected, .notAuthenticated, .userCancelled, .timedOut, .unauthorized,
    ]

    static let retryAfter = Duration.seconds(7)

    /// The specification §6 table, written independently of the implementation: a base row per code and
    /// context overrides.
    static func expected(_ code: Code, _ context: ErrorResponseContext) -> PassportError.Recovery {
        let declines = context == .deviceAuthorizationPoll || context == .authorizationResponse
        let consumesRefreshToken = context == .refreshGrant || context == .exchangeWithRefreshToken
        switch code.rawValue {
        case "invalid_grant": return consumesRefreshToken ? .reauthenticate : .none
        case "access_denied": return declines ? .none : .resourceDenied
        case "invalid_target", "insufficient_scope", "client.token_rejected": return .resourceDenied
        case "invalid_client", "unauthorized_client", "unsupported_grant_type", "invalid_request", "invalid_scope",
            "client.invalid_configuration":
            return .fixConfiguration
        case "temporarily_unavailable", "server_error", "client.transport_failure":
            return .retryLater(after: retryAfter)
        case "expired_token": return context == .deviceAuthorizationPoll ? .reauthenticate : .none
        default: return .none
        }
    }

    @Test(arguments: serverCodes + clientCodes, ErrorResponseContext.allCases)
    func recoveryTable(code: Code, context: ErrorResponseContext) {
        let actual = PassportError.recovery(for: code, context: context, statusCode: nil, retryAfter: Self.retryAfter)
        #expect(actual == Self.expected(code, context))
    }

    @Test(arguments: serverCodes, ErrorResponseContext.allCases)
    func bodyCodeDecidesRegardlessOfStatus(code: Code, context: ErrorResponseContext) {
        for status in [400, 401, 403] {
            let body = Data(#"{"error":"\#(code.rawValue)"}"#.utf8)
            let error = PassportError.fromErrorResponse(statusCode: status, headers: [:], body: body, context: context)
            #expect(error.code == code)
            #expect(error.statusCode == status)
            #expect(error.recovery == Self.expected(code, context).withoutRetryAfter)
        }
    }

    @Test func unauthorizedAccessDeniedIsAccessDenied() {
        let body = Data(#"{"error":"access_denied","error_description":"No access"}"#.utf8)
        let error = PassportError.fromErrorResponse(statusCode: 401, headers: [:], body: body, context: .other)
        #expect(error.code == .accessDenied)
        #expect(error.recovery == .resourceDenied)
        #expect(error.statusCode == 401)
        #expect(error.errorDescription == "No access")
    }

    @Test func refreshInvalidGrantEndsSessionButOtherGrantsDoNot() {
        let body = Data(#"{"error":"invalid_grant"}"#.utf8)
        func classify(_ context: ErrorResponseContext) -> PassportError.Recovery {
            PassportError.fromErrorResponse(statusCode: 400, headers: [:], body: body, context: context).recovery
        }
        #expect(classify(.refreshGrant) == .reauthenticate)
        #expect(classify(.exchangeWithRefreshToken) == .reauthenticate)
        #expect(classify(.other) == PassportError.Recovery.none)
    }

    @Test func parsesErrorURIOnlyWhenAbsolute() {
        let good = Data(#"{"error":"invalid_request","error_uri":"https://as.example.com/docs"}"#.utf8)
        let bad = Data(#"{"error":"invalid_request","error_uri":"not a uri"}"#.utf8)
        #expect(
            PassportError.fromErrorResponse(statusCode: 400, headers: [:], body: good, context: .other).errorURI
                == URL(string: "https://as.example.com/docs")
        )
        #expect(
            PassportError.fromErrorResponse(statusCode: 400, headers: [:], body: bad, context: .other).errorURI == nil)
    }

    @Test(arguments: [
        (429, PassportError.Code.temporarilyUnavailable),
        (500, .temporarilyUnavailable),
        (503, .temporarilyUnavailable),
        (599, .temporarilyUnavailable),
        (400, .invalidResponse),
        (401, .invalidResponse),
        (404, .invalidResponse),
        (302, .invalidResponse),
    ])
    func nonJSONBodyMapsByStatus(status: Int, code: Code) {
        for body in ["", "<html>oops</html>", "[1]", #"{"error":5}"#, #"{"error":""}"#, #"{"message":"x"}"#] {
            let error = PassportError.fromErrorResponse(
                statusCode: status,
                headers: ["Retry-After": "12"],
                body: Data(body.utf8),
                context: .refreshGrant
            )
            #expect(error.code == code)
            #expect(error.statusCode == status)
            let isTransient = code == .temporarilyUnavailable
            #expect(error.recovery == (isTransient ? .retryLater(after: .seconds(12)) : .none))
        }
    }

    @Test func unknownServerCodesFallBackToStatus() {
        let body = Data(#"{"error":"vendor_specific"}"#.utf8)
        let transient = PassportError.fromErrorResponse(statusCode: 503, headers: [:], body: body, context: .other)
        let permanent = PassportError.fromErrorResponse(statusCode: 400, headers: [:], body: body, context: .other)
        #expect(transient.code.rawValue == "vendor_specific")
        #expect(transient.recovery == .retryLater(after: nil))
        #expect(permanent.recovery == PassportError.Recovery.none)
    }

    @Test(arguments: [
        ("120", Duration?.some(.seconds(120))),
        (" 5 ", .some(.seconds(5))),
        ("0", .some(.seconds(0))),
        ("-1", nil),
        ("1.5", nil),
        ("abc", nil),
        ("", nil),
        ("Wed, 21 Oct 2026 07:28:00 GMT", nil),
        ("99999999999999999999999", nil),
        ("١٢", nil),
    ])
    func retryAfterSeconds(header: String, expected: Duration?) {
        #expect(PassportError.retryAfter(in: ["Retry-After": header]) == expected)
    }

    @Test(arguments: [
        ("Wed, 21 Oct 2026 07:28:30 GMT", Duration?.some(.seconds(30))),  // IMF-fixdate
        ("Wednesday, 21-Oct-26 07:29:00 GMT", .some(.seconds(60))),  // obsolete RFC 850
        ("Wed Oct 21 07:30:00 2026", .some(.seconds(120))),  // obsolete asctime
        ("Wed, 21 Oct 2026 07:00:00 GMT", .some(.seconds(0))),  // in the past
        ("Wed, 21 Oct 2026 07:28:30 PST", nil), ("tomorrow", nil),
    ])
    func retryAfterHTTPDate(header: String, expected: Duration?) {
        let now = Date(timeIntervalSince1970: 1_792_567_680)  // Wed, 21 Oct 2026 07:28:00 GMT
        #expect(PassportError.retryAfter(in: ["Retry-After": header], now: now) == expected)
        #expect(PassportError.retryAfter(in: ["Retry-After": header]) == nil)  // dates need a clock
    }

    @Test func retryAfterIsHonouredForTemporaryJSONErrors() {
        let body = Data(#"{"error":"temporarily_unavailable"}"#.utf8)
        let error = PassportError.fromErrorResponse(
            statusCode: 503,
            headers: ["retry-after": "30"],
            body: body,
            context: .refreshGrant
        )
        #expect(error.recovery == .retryLater(after: .seconds(30)))
    }
}

extension PassportError.Recovery {
    fileprivate var withoutRetryAfter: PassportError.Recovery {
        if case .retryLater = self { return .retryLater(after: nil) }
        return self
    }
}
