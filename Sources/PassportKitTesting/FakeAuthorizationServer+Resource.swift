import Foundation
import PassportKit

extension FakeAuthorizationServer {
    /// The authorization server metadata document (RFC 8414 §2).
    func metadata() -> HTTPResponse {
        let base = Self.issuer.absoluteString
        let grants = Set(clients.values.flatMap(\.allowedGrants)).map(\.rawValue).sorted()
        return jsonResponse(
            200,
            [
                "issuer": controls.advertisedIssuer, "authorization_endpoint": base + "/authorize",
                "token_endpoint": base + "/token", "device_authorization_endpoint": base + "/device_authorization",
                "revocation_endpoint": base + "/revoke", "code_challenge_methods_supported": ["S256"],
                "grant_types_supported": grants, "authorization_response_iss_parameter_supported": true,
            ])
    }

    /// The protected resource: accepts any path for a live Bearer token (RFC 6750 §3).
    func handleResource(_ request: RecordedRequest) throws -> HTTPResponse {
        let header = request.headers["Authorization"] ?? ""
        guard header.lowercased().hasPrefix("bearer ") else {
            throw challenge(401, "Bearer")  // RFC 6750 §3.1: no error code when no credentials were sent.
        }
        guard let token = liveRecord(String(header.dropFirst(7)), kind: .access) else {
            throw challenge(401, #"Bearer error="invalid_token""#)
        }
        if let required = controls.requiredScope, !required.isSubset(of: token.scope) {
            throw challenge(403, #"Bearer error="insufficient_scope", scope="\#(required.rawValue)""#)
        }
        return jsonResponse(200, ["subject": token.subject, "scope": token.scope.rawValue, "path": request.path])
    }

    private func challenge(_ status: Int, _ value: String) -> Failure {
        Failure(response: HTTPResponse(statusCode: status, headers: ["WWW-Authenticate": value]))
    }
}
