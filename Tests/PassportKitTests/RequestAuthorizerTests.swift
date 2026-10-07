import Foundation
import PassportKitTesting
import Testing

@testable import PassportKit

@Suite(.timeLimit(.minutes(1)))
struct RequestAuthorizerTests {
    private func authorizer() throws -> RequestAuthorizer {
        let manager = TokenManager(
            client: try ClientFixtures.client(RecordingTransport()), store: InMemoryCredentialStore(),
            account: CredentialAccount(service: "unit", account: "user"))
        return RequestAuthorizer(manager: manager)
    }

    private let token = AccessToken(value: Secret("opaque"), tokenType: "Bearer")

    struct Case: Sendable, CustomTestStringConvertible {
        var name: String
        var status: Int
        var challenges: [String]
        var attempt: Int
        var expected: RetryDecision
        var testDescription: String { name }
    }

    private static let invalidToken = #"Bearer error="invalid_token""#
    private static let insufficientScope = #"Bearer error="insufficient_scope", scope="admin""#
    private static let unauthorized = RetryDecision.fail(
        PassportError(.unauthorized, recovery: .resourceDenied, statusCode: 401))
    private static let scopeFailure = RetryDecision.fail(PassportError(.insufficientScope, statusCode: 401))

    static let table: [Case] = [
        Case(name: "200", status: 200, challenges: [], attempt: 0, expected: .deliver),
        Case(name: "404 after retry", status: 404, challenges: [], attempt: 1, expected: .deliver),
        Case(name: "403 without challenge", status: 403, challenges: [], attempt: 0, expected: .deliver),
        Case(
            name: "403 insufficient_scope", status: 403, challenges: [insufficientScope], attempt: 0,
            expected: .deliver),
        Case(name: "403 invalid_token", status: 403, challenges: [invalidToken], attempt: 0, expected: .deliver),
        Case(name: "401 invalid_token", status: 401, challenges: [invalidToken], attempt: 0, expected: .retry),
        Case(name: "401 bare Bearer", status: 401, challenges: ["Bearer"], attempt: 0, expected: .retry),
        Case(
            name: "401 realm only", status: 401, challenges: [#"Bearer realm="api""#], attempt: 0, expected: .retry),
        Case(name: "401 without challenge", status: 401, challenges: [], attempt: 0, expected: .retry),
        Case(
            name: "401 several lines", status: 401, challenges: [#"Basic realm="x""#, invalidToken], attempt: 0,
            expected: .retry),
        Case(
            name: "401 other error", status: 401, challenges: [#"Bearer error="invalid_request""#], attempt: 0,
            expected: .deliver),
        Case(
            name: "401 insufficient_scope", status: 401, challenges: [insufficientScope], attempt: 0,
            expected: scopeFailure),
        Case(
            name: "401 insufficient_scope after retry", status: 401, challenges: [insufficientScope], attempt: 1,
            expected: scopeFailure),
        Case(
            name: "401 invalid_token after retry", status: 401, challenges: [invalidToken], attempt: 1,
            expected: unauthorized),
        Case(name: "401 bare after retry", status: 401, challenges: [], attempt: 2, expected: unauthorized),
    ]

    @Test("RFC 6750 §3.1: the decision table", arguments: table)
    func decisionTable(_ row: Case) async throws {
        var headers = HTTPHeaders()
        for line in row.challenges { headers.append("WWW-Authenticate", line) }
        let decision = try await authorizer().evaluate(
            statusCode: row.status, headers: headers, token: token, attempt: row.attempt)
        #expect(decision == row.expected)
    }

    @Test(
        "RFC 6750 §5.3: tokens are sent over https or to loopback only",
        arguments: [
            ("https://api.example.com/x", true), ("HTTPS://api.example.com/x", true),
            ("http://localhost:8080/x", true), ("http://127.0.0.1/x", true), ("http://[::1]:9/x", true),
            ("http://api.example.com/x", false), ("http://localhost.example.com/x", false),
            ("ftp://localhost/x", false), ("file:///tmp/x", false),
        ])
    func schemeRule(_ text: String, _ allowed: Bool) async throws {
        let authorizer = try authorizer()
        let url = try #require(URL(string: text))
        // Signed out: an allowed URL gets as far as the missing token, a rejected one never does.
        let expected: PassportError.Code = allowed ? .notAuthenticated : .invalidConfiguration
        #expect(await thrownCode { _ = try await authorizer.sign(URLRequest(url: url)) } == expected)
        #expect(
            await thrownCode { _ = try await authorizer.sign(HTTPRequest(method: .get, url: url)) } == expected)
    }

    private func thrownCode(_ operation: () async throws -> Void) async -> PassportError.Code? {
        do {
            try await operation()
            return nil
        } catch let error as PassportError {
            return error.code
        } catch {
            return nil
        }
    }
}
