import Foundation
import HTTPTypes

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
        request.add(OAuthParameter.token, token.reveal())
        if let typeHint { request.add(OAuthParameter.tokenTypeHint, typeHint.rawValue) }
        let (response, body) = try await send(request)
        guard (200..<300).contains(response.status.code) else {
            throw failure(response, body: body, to: request, context: .other)
        }
    }
}
