import Foundation
import PassportKit
import Testing

/// Public metadata only: no client credentials, token requests, or protected resources.
@Suite("Live discovery", .timeLimit(.minutes(1)))
struct LiveDiscoveryTests {
    private static let issuersVariable = "PASSPORTKIT_DISCOVERY_ISSUERS"
    private static let absentHostsVariable = "PASSPORTKIT_DISCOVERY_ABSENT_HOSTS"

    private static let issuers = values(for: issuersVariable)
    private static let absentHosts = values(for: absentHostsVariable)

    @Test(
        "RFC 8414 metadata has the exact issuer and usable OAuth endpoints",
        .enabled(if: !issuers.isEmpty, "Set PASSPORTKIT_DISCOVERY_ISSUERS to opt into live network requests."),
        arguments: issuers
    )
    func fetchesMetadata(issuerString: String) async throws {
        let issuer = try Self.requireHTTPSURL(issuerString)
        let metadata = try await Discovery.fetchMetadata(issuer: issuer, style: .oauth, validation: .strict)
        #expect(metadata.issuer.absoluteString == issuerString)
        let authorization = try #require(metadata.authorizationEndpoint)
        let token = try #require(metadata.tokenEndpoint)
        #expect(authorization.scheme == "https")
        #expect(token.scheme == "https")

        // Validate that the discovered endpoints can be consumed by the public configuration API.
        let configuration = try ClientConfiguration(
            metadata: metadata, authentication: .publicClient(clientID: "discovery-integration-test"))
        #expect(configuration.issuer?.absoluteString == issuerString)
        #expect(configuration.endpoints.authorization == authorization)
        #expect(configuration.endpoints.token == token)
    }

    @Test(
        "Strict issuer validation rejects a trailing-slash difference (RFC 8414 §3.3)",
        .enabled(if: !issuers.isEmpty, "Set PASSPORTKIT_DISCOVERY_ISSUERS to opt into live network requests."),
        arguments: issuers
    )
    func rejectsDifferentIssuer(issuerString: String) async throws {
        let issuer = try Self.requireHTTPSURL(issuerString)
        let alternateString =
            issuerString.hasSuffix("/") ? String(issuerString.dropLast()) : issuerString + "/"
        let alternate = try Self.requireHTTPSURL(alternateString)

        // Both spellings locate the same document; only the issuer comparison changes.
        let metadata = try await Discovery.fetchMetadata(
            issuer: alternate, style: .oauth, validation: .expected(issuer))
        #expect(metadata.issuer.absoluteString == issuerString)
        let error = await passportError {
            _ = try await Discovery.fetchMetadata(issuer: alternate, style: .oauth, validation: .strict)
        }
        #expect(error?.code == .issuerMismatch)
    }

    @Test(
        "Resource hosts without RFC 8414 discovery return 404",
        .enabled(if: !absentHosts.isEmpty, "Set PASSPORTKIT_DISCOVERY_ABSENT_HOSTS to opt into live network requests."),
        arguments: absentHosts
    )
    func rejectsAbsentOAuthMetadata(host: String) async throws {
        try await expectAbsentMetadata(host: host, style: .oauth)
    }

    @Test(
        "Resource hosts without OpenID Connect discovery return 404",
        .enabled(if: !absentHosts.isEmpty, "Set PASSPORTKIT_DISCOVERY_ABSENT_HOSTS to opt into live network requests."),
        arguments: absentHosts
    )
    func rejectsAbsentOpenIDConnectMetadata(host: String) async throws {
        try await expectAbsentMetadata(host: host, style: .openIDConnect)
    }

    private func expectAbsentMetadata(host: String, style: Discovery.Style) async throws {
        let issuer = try Self.requireHTTPSURL(host)
        let error = await passportError {
            _ = try await Discovery.fetchMetadata(issuer: issuer, style: style, validation: .strict)
        }
        // A timeout, TLS error, malformed 200, or server outage is not evidence of absent discovery.
        #expect(error?.statusCode == 404)
    }

    private static func values(for variable: String) -> [String] {
        (ProcessInfo.processInfo.environment[variable] ?? "")
            .split(whereSeparator: { $0.isWhitespace }).map(String.init)
    }

    private static func requireHTTPSURL(_ value: String) throws -> URL {
        let url = try #require(URL(string: value), "Discovery configuration must contain absolute HTTPS URLs.")
        #expect(url.scheme == "https")
        _ = try #require(url.host)
        return url
    }
}
