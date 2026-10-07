import Foundation
import PassportKit

extension FakeAuthorizationServer {
    /// RFC 8693 token exchange for access token and refresh token subjects.
    func exchange(_ request: RecordedRequest, client: ClientRegistration, resources: [URL]) throws -> HTTPResponse {
        guard let subjectToken = request.value("subject_token"), let typeName = request.value("subject_token_type")
        else {
            throw Failure.oauth("invalid_request", "subject_token and subject_token_type are required.")
        }
        let subjectType = TokenTypeIdentifier(rawValue: typeName)
        let kind: TokenRecord.Kind
        switch subjectType {
        case .accessToken: kind = .access
        case .refreshToken: kind = .refresh
        default: throw Failure.oauth("invalid_request", "The subject token type is not supported.")
        }
        if let requested = request.value("requested_token_type"), requested != TokenTypeIdentifier.accessToken.rawValue
        {
            throw Failure.oauth("invalid_request", "Only access tokens can be requested.")
        }
        guard let subject = liveRecord(subjectToken, kind: kind) else {
            throw Failure.oauth("invalid_grant", "The subject token is invalid, expired or revoked.")
        }
        let audience = request.values("audience")
        // Audiences are logical names; only those that parse as URLs can be judged like resources.
        let targets = resources + audience.compactMap { URL(string: $0) }
        let denied = targets.contains(where: controls.isResourceUnauthorized)
        if denied && controls.exchangeForUnauthorizedResource == .accessDenied401 {
            throw Failure.oauth("access_denied", "The subject may not access the target.", status: 401)
        }
        var scope = subject.scope
        if let text = request.value("scope") {
            scope = ScopeSet(parsing: text)
            guard scope.isSubset(of: subject.scope) else {
                throw Failure.oauth("invalid_scope", "An exchange cannot widen the scope.")
            }
        }
        let granted = denied ? controls.narrowedScope : narrow(scope, subject: subject.subject, resources: resources)
        let issuance = Issuance(
            client: client, grantID: subject.grantID, subject: subject.subject, resources: resources, audience: audience
        )
        return tokenResponse(
            accessToken: mint(.access, issuance, scope: granted), scope: granted, client: client,
            issuedTokenType: .accessToken)
    }
}
