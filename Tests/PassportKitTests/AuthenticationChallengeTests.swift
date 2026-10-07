import Foundation
import Testing

@testable import PassportKit

@Suite(.timeLimit(.minutes(1)))
struct AuthenticationChallengeTests {
    private func challenge(
        _ scheme: String, _ parameters: [String: String] = [:], token68: String? = nil
    ) -> AuthenticationChallenge {
        AuthenticationChallenge(scheme: scheme, parameters: parameters, token68: token68)
    }

    struct Case: Sendable, CustomTestStringConvertible {
        var name: String
        var lines: [String]
        var expected: [AuthenticationChallenge]
        var testDescription: String { name }
    }

    private static func make(
        _ name: String, _ lines: [String], _ expected: [AuthenticationChallenge]
    ) -> Case {
        Case(name: name, lines: lines, expected: expected)
    }

    static let corpus: [Case] = [
        // RFC 6750 §3 and §3.1 examples.
        make(
            "rfc6750 realm only", [#"Bearer realm="example""#],
            [.init(scheme: "bearer", parameters: ["realm": "example"])]),
        make(
            "rfc6750 invalid_token",
            [
                #"Bearer realm="example", error="invalid_token", error_description="The access token expired""#
            ],
            [
                .init(
                    scheme: "bearer",
                    parameters: [
                        "realm": "example", "error": "invalid_token",
                        "error_description": "The access token expired",
                    ])
            ]),
        make(
            "rfc6750 insufficient_scope",
            [#"Bearer realm="example", error="insufficient_scope", scope="a b""#],
            [
                .init(
                    scheme: "bearer",
                    parameters: ["realm": "example", "error": "insufficient_scope", "scope": "a b"])
            ]),
        make("rfc6750 no parameters", ["Bearer"], [.init(scheme: "bearer")]),
        make(
            "rfc6750 invalid_request",
            [
                #"Bearer error="invalid_request", error_description="The access token is missing""#
            ],
            [
                .init(
                    scheme: "bearer",
                    parameters: ["error": "invalid_request", "error_description": "The access token is missing"])
            ]),
        // Several challenges in one value.
        make(
            "two challenges in one value",
            [#"Basic realm="x", Bearer error="insufficient_scope", scope="a b""#],
            [
                .init(scheme: "basic", parameters: ["realm": "x"]),
                .init(scheme: "bearer", parameters: ["error": "insufficient_scope", "scope": "a b"]),
            ]),
        make(
            "two header lines",
            [#"Basic realm="simple""#, #"Bearer realm="api", error="invalid_token""#],
            [
                .init(scheme: "basic", parameters: ["realm": "simple"]),
                .init(scheme: "bearer", parameters: ["realm": "api", "error": "invalid_token"]),
            ]),
        // RFC 9110 §11.6.1 example.
        make(
            "rfc9110 example",
            [#"Newauth realm="apps", type=1, title="Login to \"apps\"", Basic realm="simple""#],
            [
                .init(scheme: "newauth", parameters: ["realm": "apps", "type": "1", "title": #"Login to "apps""#]),
                .init(scheme: "basic", parameters: ["realm": "simple"]),
            ]),
        // Case-insensitivity.
        make(
            "case-insensitive scheme and names",
            [#"BEARER REALM="Example", Error="invalid_token""#],
            [.init(scheme: "bearer", parameters: ["realm": "Example", "error": "invalid_token"])]),
        // Quoting.
        make(
            "comma inside quoted string",
            [#"Bearer error_description="a, b, Basic realm=x", error="invalid_token""#],
            [
                .init(
                    scheme: "bearer",
                    parameters: ["error_description": "a, b, Basic realm=x", "error": "invalid_token"])
            ]),
        make(
            "escaped backslash and quote",
            [#"Bearer realm="a\\b\"c""#],
            [.init(scheme: "bearer", parameters: ["realm": #"a\b"c"#])]),
        make("empty quoted value", [#"Bearer realm="""#], [.init(scheme: "bearer", parameters: ["realm": ""])]),
        make(
            "unquoted token values",
            ["Digest algorithm=MD5, qop=auth"],
            [.init(scheme: "digest", parameters: ["algorithm": "MD5", "qop": "auth"])]),
        make(
            "whitespace around separators",
            ["  Bearer   realm=\"a\"  ,  scope=\"b\"  ,Basic realm=\"c\" "],
            [
                .init(scheme: "bearer", parameters: ["realm": "a", "scope": "b"]),
                .init(scheme: "basic", parameters: ["realm": "c"]),
            ]),
        make(
            "unicode in quoted string",
            [#"Bearer error_description="Zugriff verweigert: ä€""#],
            [.init(scheme: "bearer", parameters: ["error_description": "Zugriff verweigert: ä€"])]),
        make(
            "first duplicate wins", [#"Bearer realm="a", realm="b""#],
            [.init(scheme: "bearer", parameters: ["realm": "a"])]),
        // token68.
        make("token68 with padding", ["Negotiate abc=="], [.init(scheme: "negotiate", token68: "abc==")]),
        make("token68 plain", ["Negotiate YII/ab+c-d_e~f."], [.init(scheme: "negotiate", token68: "YII/ab+c-d_e~f.")]),
        make("scheme without credentials", ["Negotiate"], [.init(scheme: "negotiate")]),
        make(
            "token68 then another challenge",
            ["Negotiate abc==, Basic realm=\"x\""],
            [.init(scheme: "negotiate", token68: "abc=="), .init(scheme: "basic", parameters: ["realm": "x"])]),
        make(
            "bare schemes in a list",
            ["Negotiate, Basic realm=\"x\", NTLM"],
            [
                .init(scheme: "negotiate"), .init(scheme: "basic", parameters: ["realm": "x"]),
                .init(scheme: "ntlm"),
            ]),
        make(
            "bare scheme after a stray comma",
            ["Bearer , Basic realm=\"x\""],
            [.init(scheme: "bearer"), .init(scheme: "basic", parameters: ["realm": "x"])]),
        // DPoP (RFC 9449 §7.1) style.
        make(
            "dpop with algs",
            [#"DPoP realm="api", error="invalid_token", algs="ES256 PS256""#],
            [
                .init(
                    scheme: "dpop",
                    parameters: ["realm": "api", "error": "invalid_token", "algs": "ES256 PS256"])
            ]),
        make(
            "bearer and dpop together",
            [#"DPoP error="use_dpop_nonce", algs="ES256""#, #"Bearer realm="api""#],
            [
                .init(scheme: "dpop", parameters: ["error": "use_dpop_nonce", "algs": "ES256"]),
                .init(scheme: "bearer", parameters: ["realm": "api"]),
            ]),
    ]

    @Test(arguments: corpus) func parsesTheCorpus(_ testCase: Case) {
        #expect(AuthenticationChallenge.parse(testCase.lines) == testCase.expected)
    }

    @Test(
        arguments: [
            [], [""], ["   "], [","], [",,,"], ["="], ["=="], ["\""], [#""unterminated"#], ["\\"],
            ["Bearer realm=\"unterminated"],
            ["Bearer realm="], ["Bearer ="], ["Bearer ==x"], ["Bearer a==b"], ["Bearer \"x\""], ["1 2 3"], ["@@@"],
            ["Bearer realm=a=b"],
            ["Bearer realm=\"a\"\"b\""], ["\u{0}\u{1}\u{7f}"], ["Bearer 🙂"], ["🙂 Bearer realm=\"x\""],
            ["Bearer \\\"x\\\""],
        ] as [[String]])
    func garbageNeverCrashes(_ lines: [String]) {
        _ = AuthenticationChallenge.parse(lines)
    }

    @Test func malformedPartsAreSkippedAndLaterChallengesSurvive() {
        let parsed = AuthenticationChallenge.parse([#"@@@, Bearer realm="x""#])
        #expect(parsed.last == challenge("bearer", ["realm": "x"]))
    }

    @Test func unterminatedQuotedStringKeepsWhatWasRead() {
        #expect(AuthenticationChallenge.parse([#"Bearer realm="abc"#]) == [challenge("bearer", ["realm": "abc"])])
    }

    @Test func noHeadersMeansNoChallenges() {
        #expect(AuthenticationChallenge.parse([]).isEmpty)
        #expect(AuthenticationChallenge.parse(["", " , "]).isEmpty)
    }

    @Test func parsesHeaderLinesStraightFromHTTPHeaders() {
        var headers = HTTPHeaders()
        headers.append("WWW-Authenticate", #"Basic realm="simple""#)
        headers.append("www-authenticate", #"Bearer error="invalid_token""#)
        let parsed = AuthenticationChallenge.parse(headers.values(for: "WWW-Authenticate"))
        #expect(parsed.map(\.scheme) == ["basic", "bearer"])
    }

    @Test func longHostileInputTerminates() {
        let hostile = String(repeating: "\"\\,=", count: 20_000)
        _ = AuthenticationChallenge.parse([hostile, String(repeating: "Bearer a=\"", count: 5_000)])
    }
}
