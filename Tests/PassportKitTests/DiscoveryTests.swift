import Foundation
import Testing

@testable import PassportKit

@Suite(.timeLimit(.minutes(1)))
struct DiscoveryTests {
    private static func metadataJSON(
        issuer: String = "https://as.example.com", extra: String = ""
    ) -> String {
        #"{"issuer":"\#(issuer)","authorization_endpoint":"https://as.example.com/authorize","#
            + #""token_endpoint":"https://as.example.com/token","device_authorization_endpoint":"https://as.example.com/device","#
            + #""revocation_endpoint":"https://as.example.com/revoke","code_challenge_methods_supported":["S256"],"#
            + #""grant_types_supported":["authorization_code","refresh_token"],"#
            + #""authorization_response_iss_parameter_supported":true\#(extra)}"#
    }

    // RFC 8414 §3.1 and OpenID Connect Discovery §4.
    @Test(
        arguments: [
            (
                "https://as.example.com", Discovery.Style.oauth,
                "https://as.example.com/.well-known/oauth-authorization-server"
            ),
            ("https://as.example.com/", .oauth, "https://as.example.com/.well-known/oauth-authorization-server"),
            (
                "https://as.example.com/issuer1", .oauth,
                "https://as.example.com/.well-known/oauth-authorization-server/issuer1"
            ),
            (
                "https://as.example.com/issuer1/", .oauth,
                "https://as.example.com/.well-known/oauth-authorization-server/issuer1"
            ),
            (
                "https://as.example.com/a/b", .oauth,
                "https://as.example.com/.well-known/oauth-authorization-server/a/b"
            ),
            (
                "https://as.example.com:8443/t", .oauth,
                "https://as.example.com:8443/.well-known/oauth-authorization-server/t"
            ),
            ("https://as.example.com", .openIDConnect, "https://as.example.com/.well-known/openid-configuration"),
            ("https://as.example.com/", .openIDConnect, "https://as.example.com/.well-known/openid-configuration"),
            (
                "https://as.example.com/issuer1", .openIDConnect,
                "https://as.example.com/issuer1/.well-known/openid-configuration"
            ),
            (
                "https://as.example.com/issuer1/", .openIDConnect,
                "https://as.example.com/issuer1/.well-known/openid-configuration"
            ),
            (
                "http://localhost:8080/realm", .oauth,
                "http://localhost:8080/.well-known/oauth-authorization-server/realm"
            ),
        ])
    func wellKnownURLConstruction(issuer: String, style: Discovery.Style, expected: String) throws {
        #expect(try Discovery.metadataURL(for: URL(string: issuer)!, style: style).absoluteString == expected)
    }

    @Test(arguments: [
        "https://as.example.com?x=1", "https://as.example.com/a#f", "http://as.example.com",
        "https://u:p@as.example.com",
    ])
    func unsuitableIssuersAreRejected(_ issuer: String) async throws {
        let transport = RecordingTransport()
        let error = try await #require(throws: PassportError.self) {
            try await Discovery.fetchMetadata(issuer: URL(string: issuer)!, transport: transport)
        }
        #expect(error.code == .invalidConfiguration)
        #expect(await transport.requests.isEmpty)
    }

    @Test func fetchesWithGetAndParsesEveryKnownMember() async throws {
        let transport = RecordingTransport([.json(200, Self.metadataJSON())])
        let metadata = try await Discovery.fetchMetadata(
            issuer: URL(string: "https://as.example.com")!, transport: transport)
        let sent = try #require(await transport.requests.first)
        #expect(sent.request.method == .get)
        #expect(sent.request.body == nil)
        #expect(sent.request.headers["Accept"] == "application/json")
        #expect(sent.request.url.absoluteString == "https://as.example.com/.well-known/oauth-authorization-server")
        #expect(metadata.issuer.absoluteString == "https://as.example.com")
        #expect(metadata.authorizationEndpoint?.path == "/authorize")
        #expect(metadata.tokenEndpoint?.path == "/token")
        #expect(metadata.deviceAuthorizationEndpoint?.path == "/device")
        #expect(metadata.revocationEndpoint?.path == "/revoke")
        #expect(metadata.codeChallengeMethodsSupported == ["S256"])
        #expect(metadata.grantTypesSupported == ["authorization_code", "refresh_token"])
        #expect(metadata.authorizationResponseIssParameterSupported == true)
        #expect(metadata.additionalFields.isEmpty)
    }

    @Test func unknownMembersArePreservedAndRoundTrip() async throws {
        let extra = #","x_vendor":{"a":[1,"b",null]},"scopes_supported":["openid"],"x_flag":false"#
        let transport = RecordingTransport([.json(200, Self.metadataJSON(extra: extra))])
        let metadata = try await Discovery.fetchMetadata(
            issuer: URL(string: "https://as.example.com")!, transport: transport)
        #expect(
            metadata.additionalFields == [
                "x_vendor": .object(["a": .array([.number(1), .string("b"), .null])]),
                "scopes_supported": .array([.string("openid")]),
                "x_flag": .bool(false),
            ])
        let encoded = try JSONEncoder().encode(metadata)
        #expect(try JSONDecoder().decode(AuthorizationServerMetadata.self, from: encoded) == metadata)
        let text = String(decoding: encoded, as: UTF8.self)
        #expect(text.contains("\"token_endpoint\""))
        #expect(!text.contains("tokenEndpoint"))
    }

    @Test func issuerPathUsesTheInsertedWellKnownURL() async throws {
        let transport = RecordingTransport([.json(200, Self.metadataJSON(issuer: "https://as.example.com/tenant"))])
        _ = try await Discovery.fetchMetadata(
            issuer: URL(string: "https://as.example.com/tenant")!, transport: transport)
        let sent = try #require(await transport.requests.first)
        #expect(
            sent.request.url.absoluteString == "https://as.example.com/.well-known/oauth-authorization-server/tenant")
    }

    @Test func openIDConnectStyleUsesItsOwnPath() async throws {
        let transport = RecordingTransport([.json(200, Self.metadataJSON(issuer: "https://as.example.com/tenant"))])
        _ = try await Discovery.fetchMetadata(
            issuer: URL(string: "https://as.example.com/tenant")!, style: .openIDConnect, transport: transport)
        let sent = try #require(await transport.requests.first)
        #expect(sent.request.url.absoluteString == "https://as.example.com/tenant/.well-known/openid-configuration")
    }

    // MARK: Issuer validation

    @Test(arguments: ["https://evil.example.com", "https://as.example.com/", "http://as.example.com"])
    func strictValidationRequiresTheIdenticalIssuer(_ served: String) async throws {
        let transport = RecordingTransport([.json(200, Self.metadataJSON(issuer: served))])
        let error = try await #require(throws: PassportError.self) {
            try await Discovery.fetchMetadata(issuer: URL(string: "https://as.example.com")!, transport: transport)
        }
        #expect(error.code == .issuerMismatch)
    }

    @Test func expectedValidationComparesWithTheGivenIssuer() async throws {
        let served = Self.metadataJSON(issuer: "https://login.example.com")
        let ok = RecordingTransport([.json(200, served)])
        let metadata = try await Discovery.fetchMetadata(
            issuer: URL(string: "https://as.example.com")!,
            validation: .expected(URL(string: "https://login.example.com")!), transport: ok)
        #expect(metadata.issuer.host == "login.example.com")

        let wrong = RecordingTransport([.json(200, served)])
        let error = try await #require(throws: PassportError.self) {
            try await Discovery.fetchMetadata(
                issuer: URL(string: "https://as.example.com")!,
                validation: .expected(URL(string: "https://other.example.com")!), transport: wrong)
        }
        #expect(error.code == .issuerMismatch)
    }

    @Test func disabledValidationAcceptsAnyIssuer() async throws {
        let transport = RecordingTransport([.json(200, Self.metadataJSON(issuer: "https://elsewhere.example.com"))])
        let metadata = try await Discovery.fetchMetadata(
            issuer: URL(string: "https://as.example.com")!, validation: .disabled, transport: transport)
        #expect(metadata.issuer.host == "elsewhere.example.com")
    }

    // MARK: Failures

    @Test(arguments: [
        "", "[]", "not json", "{}", #"{"issuer":42}"#, #"{"issuer":"https://as.example.com","token_endpoint":5}"#,
        #"{"issuer":"https://as.example.com","grant_types_supported":"code"}"#,
    ])
    func malformedMetadataIsAnInvalidResponse(_ body: String) async throws {
        let transport = RecordingTransport([.json(200, body)])
        let error = try await #require(throws: PassportError.self) {
            try await Discovery.fetchMetadata(issuer: URL(string: "https://as.example.com")!, transport: transport)
        }
        #expect(error.code == .invalidResponse)
    }

    @Test func errorStatusesAreErrors() async throws {
        let notFound = RecordingTransport([.json(404, "<html>nope</html>")])
        let missing = try await #require(throws: PassportError.self) {
            try await Discovery.fetchMetadata(issuer: URL(string: "https://as.example.com")!, transport: notFound)
        }
        #expect(missing.code == .invalidResponse)
        #expect(missing.statusCode == 404)

        let busy = RecordingTransport([.json(503, "", headers: ["Retry-After": "7"])])
        let unavailable = try await #require(throws: PassportError.self) {
            try await Discovery.fetchMetadata(issuer: URL(string: "https://as.example.com")!, transport: busy)
        }
        #expect(unavailable.code == .temporarilyUnavailable)
        #expect(unavailable.recovery == .retryLater(after: .seconds(7)))
    }

    @Test func transportFailuresAreWrappedAndCancellationPropagates() async throws {
        let failing = RecordingTransport([.fail(URLError(.notConnectedToInternet))])
        let error = try await #require(throws: PassportError.self) {
            try await Discovery.fetchMetadata(issuer: URL(string: "https://as.example.com")!, transport: failing)
        }
        #expect(error.code == .transportFailure)

        let cancelling = RecordingTransport([.fail(CancellationError())])
        await #expect(throws: CancellationError.self) {
            try await Discovery.fetchMetadata(issuer: URL(string: "https://as.example.com")!, transport: cancelling)
        }
    }

    // MARK: Endpoints

    @Test func endpointsComeFromMetadata() throws {
        let metadata = try JSONDecoder().decode(
            AuthorizationServerMetadata.self, from: Data(Self.metadataJSON().utf8))
        let endpoints = try Endpoints(metadata: metadata)
        #expect(endpoints.authorization?.path == "/authorize")
        #expect(endpoints.token.path == "/token")
        #expect(endpoints.deviceAuthorization?.path == "/device")
        #expect(endpoints.revocation?.path == "/revoke")
    }

    @Test func endpointsNeedATokenEndpointAndSecureURLs() throws {
        let issuer = URL(string: "https://as.example.com")!
        let missing = try #require(throws: PassportError.self) {
            try Endpoints(metadata: AuthorizationServerMetadata(issuer: issuer))
        }
        #expect(missing.code == .invalidConfiguration)
        let insecure = AuthorizationServerMetadata(
            issuer: issuer, tokenEndpoint: URL(string: "http://as.example.com/t")!)
        #expect(throws: PassportError.self) { try Endpoints(metadata: insecure) }
    }
}
