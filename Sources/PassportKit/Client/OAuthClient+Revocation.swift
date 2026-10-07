import Foundation

extension OAuthClient {
    /// Revokes a token (RFC 7009 §2).
    ///
    /// Any 2xx response is success regardless of its body (§2.2: unknown or already revoked tokens also
    /// answer 200). A 503 is reported as ``PassportError/Code-swift.struct/temporarilyUnavailable`` with
    /// `Retry-After` honoured (§2.2.1). Throws `invalidConfiguration` when no revocation endpoint is configured.
    public func revoke(_ token: Secret, typeHint: TokenTypeHint? = nil) async throws {
        var request = FormRequest(
            endpoint: .revocation,
            url: try requireEndpoint(configuration.endpoints.revocation, name: "revocation")
        )
        request.add("token", token.reveal())
        if let typeHint { request.add("token_type_hint", typeHint.rawValue) }
        let response = try await send(request)
        guard (200..<300).contains(response.statusCode) else {
            throw failure(response, to: request, context: .other)
        }
    }
}
