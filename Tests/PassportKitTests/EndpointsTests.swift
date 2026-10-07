import Foundation
import Testing

@testable import PassportKit

struct EndpointsTests {
    private func validates(_ token: String, authorization: String? = nil) -> Bool {
        let endpoints = Endpoints(authorization: authorization.flatMap(URL.init(string:)), token: URL(string: token)!)
        return (try? endpoints.validate()) != nil
    }

    @Test(arguments: [
        "https://as.example.com/token",
        "HTTPS://as.example.com/token",
        "http://localhost/token",
        "http://LOCALHOST:8080/token",
        "http://127.0.0.1:9000/token",
        "http://[::1]:9000/token",
    ])
    func acceptsHTTPSAndLoopbackHTTP(url: String) {
        #expect(validates(url))
    }

    @Test(arguments: [
        "http://as.example.com/token",
        "http://localhost.example.com/token",
        "http://127.0.0.2/token",
        "http://192.168.1.1/token",
        "ftp://as.example.com/token",
        "https:///token",
        "as.example.com/token",
    ])
    func rejectsOtherEndpoints(url: String) {
        #expect(!validates(url))
    }

    @Test func rejectsInsecureOptionalEndpoints() {
        #expect(!validates("https://as.example.com/token", authorization: "http://as.example.com/authorize"))
        #expect(validates("https://as.example.com/token", authorization: "https://as.example.com/authorize"))
    }

    @Test func configurationValidatesEndpointsAndIssuer() {
        let endpoints = Endpoints(token: URL(string: "https://as.example.com/token")!)
        var configuration = ClientConfiguration(endpoints: endpoints, authentication: .publicClient(clientID: "app"))
        #expect((try? configuration.validate()) != nil)
        configuration.issuer = URL(string: "http://as.example.com")
        #expect {
            try configuration.validate()
        } throws: { error in
            (error as? PassportError)?.code == .invalidConfiguration
        }
    }

    @Test func configurationDefaults() {
        let configuration = ClientConfiguration(
            endpoints: Endpoints(token: URL(string: "https://as.example.com/token")!),
            authentication: .publicClient(clientID: "app")
        )
        #expect(configuration.minimumTokenLifetime == .seconds(60))
        #expect(configuration.defaultTokenLifetime == nil)
        #expect(configuration.additionalHeaders.names.isEmpty)
    }
}

struct ConfigurationFromMetadataTests {
    private func metadata(issuerParameter: Bool?) -> AuthorizationServerMetadata {
        AuthorizationServerMetadata(
            issuer: URL(string: "https://as.example.com")!,
            authorizationEndpoint: URL(string: "https://as.example.com/authorize")!,
            tokenEndpoint: URL(string: "https://as.example.com/token")!,
            authorizationResponseIssParameterSupported: issuerParameter
        )
    }

    @Test(arguments: [(true as Bool?, true), (false, false), (nil, false)])
    func requiresIssuerWhenAdvertised(advertised: Bool?, expected: Bool) throws {
        let configuration = try ClientConfiguration(
            metadata: metadata(issuerParameter: advertised), authentication: .publicClient(clientID: "app"))
        #expect(configuration.requiresIssuerInAuthorizationResponse == expected)
        #expect(configuration.issuer == URL(string: "https://as.example.com"))
        #expect(configuration.endpoints.token == URL(string: "https://as.example.com/token"))
    }

    @Test func rejectsMetadataWithoutTokenEndpoint() {
        let bare = AuthorizationServerMetadata(issuer: URL(string: "https://as.example.com")!)
        #expect(throws: PassportError.self) {
            try ClientConfiguration(metadata: bare, authentication: .publicClient(clientID: "app"))
        }
    }
}
