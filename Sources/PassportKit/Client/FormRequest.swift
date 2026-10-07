import Foundation

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
        parameters.add("grant_type", grantType.rawValue)
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
    func build(configuration: ClientConfiguration) throws -> HTTPRequest {
        var headers = HTTPHeaders()
        for (name, value) in configuration.additionalHeaders { headers.add(name: name, value: value) }
        var standard = parameters.items
        configuration.authentication.apply(to: &standard, headers: &headers)
        let all = try additionalParameters.appending(to: standard, reserving: ClientAuthentication.parameterNames)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Accept"] = "application/json"
        return HTTPRequest(method: .post, url: url, headers: headers, body: FormEncoding.encode(all))
    }
}
