import Foundation
import PassportKitTesting
import Testing

@testable import PassportKit

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

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
        Case(
            name: "401 Basic only", status: 401, challenges: [#"Basic realm="x""#], attempt: 0, expected: .deliver),
        Case(
            name: "401 DPoP only", status: 401, challenges: [#"DPoP error="invalid_token", algs="ES256""#],
            attempt: 0, expected: .deliver),
        Case(
            name: "401 Basic only after retry", status: 401, challenges: [#"Basic realm="x""#], attempt: 1,
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

    private func signedIn(
        token: String = "opaque", tokenType: String = "Bearer", allowedOrigins: Set<URL>? = nil
    ) async throws -> RequestAuthorizer {
        let manager = TokenManager(
            client: try ClientFixtures.client(RecordingTransport()), store: InMemoryCredentialStore(),
            account: CredentialAccount(service: "unit", account: "user"))
        try await manager.signIn(
            with: TokenResponse(accessToken: Secret(token), tokenType: tokenType, expiresIn: .seconds(3600)))
        return RequestAuthorizer(manager: manager, allowedOrigins: allowedOrigins)
    }

    @Test(
        "an origin allow-list limits where a token goes, before a token is obtained",
        arguments: [
            ("https://api.example.com/v1/items?x=1", true), ("HTTPS://API.EXAMPLE.COM:443/", true),
            ("https://api.example.com:8443/", false), ("http://localhost:8080/x", true),
            ("https://api.example.com.evil.example/", false), ("https://evil.example/", false),
            ("http://api.example.com/", false),
        ])
    func allowedOrigins(_ text: String, _ allowed: Bool) async throws {
        let origins = ["https://api.example.com/ignored/path", "http://localhost:8080"].compactMap { URL(string: $0) }
        let authorizer = try await signedIn(allowedOrigins: Set(origins))
        let url = try #require(URL(string: text))
        let result = await thrownCode { _ = try await authorizer.sign(HTTPRequest(method: .get, url: url)) }
        #expect(result == (allowed ? nil : .invalidConfiguration))
    }

    @Test("an authorizer without an allow-list sends to any https origin")
    func noAllowList() async throws {
        let authorizer = try await signedIn()
        let url = try #require(URL(string: "https://evil.example/"))
        let (signed, _) = try await authorizer.sign(HTTPRequest(method: .get, url: url))
        #expect(signed.headers["Authorization"] == "Bearer opaque")
    }

    @Test(
        "RFC 6750 §2.1: a token that is not a b64token never reaches a header",
        arguments: [
            ("abc-._~+/=", true), ("A1==", true), ("", false), ("=", false), ("a b", false), ("a\r\nX: y", false),
            ("a=b", false), ("tøken", false), ("a\"b", false),
        ])
    func tokenSyntax(_ token: String, _ valid: Bool) async throws {
        let authorizer = try await signedIn(token: token)
        let url = try #require(URL(string: "https://api.example.com/x"))
        let code = await thrownCode { _ = try await authorizer.sign(HTTPRequest(method: .get, url: url)) }
        #expect(code == (valid ? nil : .invalidResponse))
    }

    @Test("data(for:session:) does not let the token follow a cross-origin redirect")
    func sessionRedirectsDropTheToken() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }
        let authorizer = try await signedIn()
        let (body, _) = try await authorizer.data(
            for: URLRequest(url: try #require(URL(string: "https://as.example.com/other-host-echo"))),
            session: session)
        #expect(String(decoding: body, as: UTF8.self) == "none")
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
