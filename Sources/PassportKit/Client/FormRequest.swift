import Foundation

/// A form-encoded POST to an authorization server endpoint, built from standard parameters, client
/// authentication and additional parameters (in that order).
struct FormRequest {
    var endpoint: EndpointKind
    var url: URL
    var grantType: GrantType?
    /// Standard parameters in wire order.
    var parameters: [(String, String)] = []
    var additionalParameters = AdditionalParameters()

    /// A token endpoint request; `grant_type` is the first parameter.
    init(tokenEndpoint url: URL, grantType: GrantType) {
        endpoint = .token
        self.url = url
        self.grantType = grantType
        parameters = [("grant_type", grantType.rawValue)]
    }

    /// A request to a non-token endpoint.
    init(endpoint: EndpointKind, url: URL) {
        self.endpoint = endpoint
        self.url = url
    }

    mutating func add(_ name: String, _ value: String) {
        parameters.append((name, value))
    }

    mutating func add(scope: ScopeSet?) {
        if let scope, !scope.isEmpty { add("scope", scope.rawValue) }
    }

    /// Adds repeated `resource` parameters (RFC 8707 §2): absolute URLs without a fragment.
    mutating func add(resources: [URL]) throws {
        for resource in resources {
            let text = resource.absoluteString
            guard resource.scheme != nil, resource.host?.isEmpty == false, !text.contains("#") else {
                throw PassportError(
                    .invalidConfiguration,
                    errorDescription: "A resource indicator must be an absolute URL without a fragment."
                )
            }
            add("resource", text)
        }
    }

    /// Applies client authentication and additional parameters and encodes the request.
    ///
    /// Library-owned headers win over `additionalHeaders` with the same name.
    func build(configuration: ClientConfiguration) throws -> HTTPRequest {
        var headers = HTTPHeaders()
        for (name, value) in configuration.additionalHeaders { headers.add(name: name, value: value) }
        var standard = parameters
        configuration.authentication.apply(to: &standard, headers: &headers)
        let all = try additionalParameters.appending(to: standard)
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Accept"] = "application/json"
        return HTTPRequest(method: .post, url: url, headers: headers, body: FormEncoding.encode(all))
    }
}
