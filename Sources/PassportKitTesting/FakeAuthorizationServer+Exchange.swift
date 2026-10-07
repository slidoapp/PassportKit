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
        let requestedType = request.value("requested_token_type").map { TokenTypeIdentifier(rawValue: $0) }
        guard
            requestedType == nil || requestedType == .accessToken
                || (requestedType == .refreshToken && kind == .refresh)
        else {
            throw Failure.oauth("invalid_request", "The requested token type is not supported for this subject.")
        }
        guard var subject = liveRecord(subjectToken, kind: kind), subject.clientID == client.id else {
            throw Failure.oauth("invalid_grant", "The subject token is invalid, expired or revoked.")
        }
        // A refresh token subject is spent like in a refresh grant: rotation applies, and a retired token is
        // answered with invalid_grant outside the leeway.
        var current = subjectToken
        var isReuse = false
        if kind == .refresh {
            (current, isReuse) = try resolveRotation(of: subjectToken, record: &subject, client: client)
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
        let rootIssuance = Issuance(
            client: client, grantID: subject.grantID, subject: subject.subject, resources: subject.resources,
            audience: subject.audience)
        let rotated =
            kind == .refresh
            ? rotate(current, isReuse: isReuse, issuance: rootIssuance, scope: subject.scope, client: client) : nil
        if requestedType == .refreshToken {
            // The issued token is itself a refresh token, carried in access_token (RFC 8693 §2.2.1).
            let issued = mint(.refresh, issuance, scope: granted)
            return tokenResponse(
                accessToken: issued, scope: granted, client: client, refreshToken: rotated,
                issuedTokenType: .refreshToken, tokenType: "N_A")
        }
        return tokenResponse(
            accessToken: mint(.access, issuance, scope: granted), scope: granted, client: client,
            refreshToken: rotated, issuedTokenType: .accessToken)
    }
}
