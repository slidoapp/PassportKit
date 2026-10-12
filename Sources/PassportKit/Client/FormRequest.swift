import Foundation
import HTTPTypes

/// A form-encoded POST to an authorization server endpoint, built from standard parameters, client
/// authentication and additional parameters (in that order).
struct FormRequest {
    var endpoint: EndpointKind
    var url: URL
    var grantType: GrantType?
    /// Standard parameters in wire order.
    var parameters = ParameterList()
    var additionalParameters = AdditionalParameters()

    /// A token endpoint request; `grant_type` is the first parameter.
    init(tokenEndpoint url: URL, grantType: GrantType) {
        endpoint = .token
        self.url = url
        self.grantType = grantType
        parameters.add(OAuthParameter.grantType, grantType.rawValue)
    }

    /// A request to a non-token endpoint.
    init(endpoint: EndpointKind, url: URL) {
        self.endpoint = endpoint
        self.url = url
    }

    mutating func add(_ name: String, _ value: String) { parameters.add(name, value) }

    mutating func add(scope: ScopeSet?) { parameters.add(scope: scope) }

    mutating func add(resources: [URL]) throws { try parameters.add(resources: resources) }

    /// Applies client authentication and additional parameters and encodes the request.
    ///
    /// Library-owned headers win over `additionalHeaders` with the same name.
    func build(configuration: ClientConfiguration) throws -> (request: HTTPRequest, body: Data) {
        var headers = configuration.additionalHeaders
        var standard = parameters.items
        configuration.authentication.apply(to: &standard, headers: &headers)
        let all = try additionalParameters.appending(to: standard, reserving: ClientAuthentication.parameterNames)
        headers[.contentType] = MediaType.formURLEncoded
        headers[.accept] = MediaType.json
        return (HTTPRequest(method: .post, url: url, headerFields: headers), FormEncoding.encode(all))
    }

    /// Parameter names whose values are credentials, in standard and additional parameters.
    private static let secretParameterNames: Set<String> = [
        OAuthParameter.refreshToken, OAuthParameter.subjectToken, OAuthParameter.actorToken, OAuthParameter.code,
        OAuthParameter.codeVerifier, OAuthParameter.deviceCode, OAuthParameter.token, OAuthParameter.clientSecret,
        OAuthParameter.assertion, OAuthParameter.clientAssertion, OAuthParameter.password,
    ]

    /// The credential values of this request and of the client authentication, which a server must not be able
    /// to make the library repeat in an error.
    func secretValues(configuration: ClientConfiguration) -> [String] {
        var values = (parameters.items + additionalParameters.items.map { ($0.name, $0.value) })
            .filter { Self.secretParameterNames.contains($0.0) }.map(\.1)
        if let secret = configuration.authentication.secret { values.append(secret.reveal()) }
        return values
    }
}
