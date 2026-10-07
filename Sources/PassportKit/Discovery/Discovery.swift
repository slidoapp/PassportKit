import Foundation

/// How the metadata `issuer` is checked against the issuer that was requested (RFC 8414 §3.3).
public enum IssuerValidation: Sendable {
    /// The metadata `issuer` must be identical to the requested issuer: a string comparison, so a trailing
    /// slash difference is a mismatch.
    case strict
    /// The metadata `issuer` must be identical to this URL, for example when the metadata is fetched through
    /// a proxy or from a different location than the issuer it describes.
    case expected(URL)
    /// No check. Only for servers known to publish a wrong `issuer`; it removes the protection against
    /// metadata impersonation (RFC 8414 §3.3, §6.2).
    case disabled
}

/// Authorization server metadata discovery (RFC 8414).
public enum Discovery {
    /// Where the well-known document is looked up.
    public enum Style: Sendable {
        /// RFC 8414 §3.1: `/.well-known/oauth-authorization-server` inserted between host and path.
        case oauth
        /// OpenID Connect Discovery §4: `/.well-known/openid-configuration` appended to the issuer path.
        case openIDConnect
    }

    /// Fetches and validates the metadata of `issuer` (RFC 8414 §3).
    ///
    /// Sends `GET` with `Accept: application/json`. A non-2xx response is classified like any server error
    /// (``PassportError/Code-swift.struct/temporarilyUnavailable`` for 429 and 5xx, otherwise the body's
    /// `error` or ``PassportError/Code-swift.struct/invalidResponse``). A body that is not a JSON object with
    /// an `issuer` and well-formed members is ``PassportError/Code-swift.struct/invalidResponse``; an issuer
    /// that fails `validation` is ``PassportError/Code-swift.struct/issuerMismatch``. The issuer must be an
    /// `https` URL (or `http` on loopback) without query or fragment, else `invalidConfiguration`.
    public static func fetchMetadata(
        issuer: URL,
        style: Style = .oauth,
        validation: IssuerValidation = .strict,
        transport: any HTTPTransport = URLSessionTransport()
    ) async throws -> AuthorizationServerMetadata {
        let request = HTTPRequest(
            method: .get,
            url: try metadataURL(for: issuer, style: style),
            headers: ["Accept": "application/json"]
        )
        let response: HTTPResponse
        do {
            response = try await transport.send(request)
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            if Task.isCancelled { throw CancellationError() }
            throw PassportError(
                .transportFailure,
                errorDescription: "The metadata request failed.",
                underlying: error
            )
        }
        guard (200..<300).contains(response.statusCode) else {
            throw PassportError.fromErrorResponse(
                statusCode: response.statusCode,
                headers: response.headers,
                body: response.body,
                context: .other
            )
        }
        let metadata: AuthorizationServerMetadata
        do {
            metadata = try JSONDecoder().decode(AuthorizationServerMetadata.self, from: response.body)
        } catch {
            throw PassportError(.invalidResponse, errorDescription: "The metadata response is not valid metadata.")
        }
        switch validation {
        case .strict: try require(metadata.issuer, equals: issuer)
        case .expected(let expected): try require(metadata.issuer, equals: expected)
        case .disabled: break
        }
        return metadata
    }

    /// The well-known URL for `issuer` (RFC 8414 §3.1).
    ///
    /// Terminating slashes of the issuer path are removed first. For `https://as.example.com/tenant/a`
    /// the `oauth` style gives `https://as.example.com/.well-known/oauth-authorization-server/tenant/a` and the
    /// `openIDConnect` style `https://as.example.com/tenant/a/.well-known/openid-configuration`.
    static func metadataURL(for issuer: URL, style: Style) throws -> URL {
        try Endpoints.validateSecureTransport(of: issuer, name: "issuer")
        guard var components = URLComponents(url: issuer, resolvingAgainstBaseURL: false),
            components.query == nil, components.fragment == nil, components.user == nil, components.password == nil
        else {
            throw PassportError(
                .invalidConfiguration,
                errorDescription: "The issuer must not contain a query, fragment or userinfo."
            )
        }
        var path = components.percentEncodedPath
        while path.hasSuffix("/") { path.removeLast() }
        switch style {
        case .oauth: components.percentEncodedPath = "/.well-known/oauth-authorization-server" + path
        case .openIDConnect: components.percentEncodedPath = path + "/.well-known/openid-configuration"
        }
        guard let url = components.url else {
            throw PassportError(.invalidConfiguration, errorDescription: "The metadata URL could not be built.")
        }
        return url
    }

    private static func require(_ actual: URL, equals expected: URL) throws {
        guard actual.absoluteString == expected.absoluteString else {
            throw PassportError(
                .issuerMismatch,
                errorDescription: "The metadata issuer differs from the expected issuer."
            )
        }
    }
}
