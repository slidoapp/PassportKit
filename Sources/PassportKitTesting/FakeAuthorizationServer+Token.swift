import Foundation
import PassportKit

struct TokenRecord {
    enum Kind { case access, refresh }
    var kind: Kind
    var grantID: Int
    var clientID: String
    var subject: String
    var scope: ScopeSet
    var resources: [URL]
    var audience: [String]
    var expiresAt: Date?
    /// The refresh token that replaced this one by rotation.
    var successor: String?
    var rotatedAt: Date?
    var reuseCount = 0
}

/// Who a token is issued to and for what; shared by every grant handler.
struct Issuance {
    var client: FakeAuthorizationServer.ClientRegistration
    var grantID: Int
    var subject: String
    var resources: [URL]
    var audience: [String] = []
}

extension FakeAuthorizationServer {
    func handleToken(_ request: RecordedRequest) throws -> HTTPResponse {
        let client = try authenticate(request)
        guard let name = request.value("grant_type") else {
            throw Failure.oauth("invalid_request", "The grant_type parameter is required.")
        }
        let grant = GrantType(rawValue: name)
        guard
            ([.authorizationCode, .refreshToken, .clientCredentials, .deviceCode, .tokenExchange] as [GrantType])
                .contains(grant)
        else {
            throw Failure.oauth("unsupported_grant_type")
        }
        guard client.allowedGrants.contains(grant) else { throw Failure.oauth("unauthorized_client") }
        let resources = try resources(of: request)
        switch grant {
        case .authorizationCode: return try redeemCode(request, client: client, resources: resources)
        case .refreshToken: return try refresh(request, client: client, resources: resources)
        case .deviceCode: return try pollDevice(request, client: client)
        case .tokenExchange: return try exchange(request, client: client, resources: resources)
        default: return try clientCredentials(request, client: client, resources: resources)
        }
    }

    func mint(_ kind: TokenRecord.Kind, _ issuance: Issuance, scope: ScopeSet) -> String {
        let token = nextIdentifier(kind == .access ? "access" : "refresh")
        let lifetime = kind == .access ? issuance.client.accessTokenLifetime : issuance.client.refreshTokenLifetime
        tokens[token] = TokenRecord(
            kind: kind, grantID: issuance.grantID, clientID: issuance.client.id, subject: issuance.subject,
            scope: scope, resources: issuance.resources, audience: issuance.audience,
            expiresAt: lifetime.map { now().addingTimeInterval($0.timeInterval) })
        return token
    }

    func tokenResponse(
        accessToken: String, scope: ScopeSet, client: ClientRegistration, refreshToken: String? = nil,
        issuedTokenType: TokenTypeIdentifier? = nil, tokenType: String = "Bearer"
    ) -> HTTPResponse {
        var body: [String: Any] = [
            "access_token": accessToken, "token_type": tokenType,
            "expires_in": Int(client.accessTokenLifetime.timeInterval),
            "scope": scope.rawValue,
        ]
        body["refresh_token"] = refreshToken
        body["issued_token_type"] = issuedTokenType?.rawValue
        return jsonResponse(200, body, headers: ["Cache-Control": "no-store", "Pragma": "no-cache"])
    }

    /// Issues an access token and, when the client may refresh, a refresh token for a new grant.
    func issueNewGrant(
        client: ClientRegistration, subject: String, scope: ScopeSet, resources: [URL], withRefreshToken: Bool
    ) -> HTTPResponse {
        let issuance = Issuance(client: client, grantID: nextGrantID(), subject: subject, resources: resources)
        let granted = narrow(scope, subject: subject, resources: resources)
        let refreshToken =
            withRefreshToken && client.allowedGrants.contains(.refreshToken)
            ? mint(.refresh, issuance, scope: scope) : nil
        let accessToken = mint(.access, issuance, scope: granted)
        return tokenResponse(accessToken: accessToken, scope: granted, client: client, refreshToken: refreshToken)
    }

    private func clientCredentials(
        _ request: RecordedRequest, client: ClientRegistration, resources: [URL]
    ) throws -> HTTPResponse {
        let scope = try requestedScope(request.value("scope"), client: client)
        return issueNewGrant(
            client: client, subject: client.id, scope: scope, resources: resources, withRefreshToken: false)
    }

    private func redeemCode(
        _ request: RecordedRequest, client: ClientRegistration, resources: [URL]
    ) throws -> HTTPResponse {
        guard let name = request.value("code"), let code = codes[name], code.clientID == client.id else {
            throw Failure.oauth("invalid_grant", "The authorization code is unknown.")
        }
        codes[name]?.isUsed = true
        guard !code.isUsed else {
            revokeGrant(code.grantID)  // RFC 6749 §4.1.2: a replayed code revokes what it issued.
            throw Failure.oauth("invalid_grant", "The authorization code was already used.")
        }
        guard code.expiresAt > now(), request.value("redirect_uri") == code.redirectURI else {
            throw Failure.oauth("invalid_grant", "The authorization code is expired or the redirect URI differs.")
        }
        if let challenge = code.codeChallenge {
            let verifier = request.value("code_verifier") ?? ""
            guard (43...128).contains(verifier.utf8.count), PKCEChallenge.s256(verifier) == challenge else {
                throw Failure.oauth("invalid_grant", "The PKCE code verifier does not match the challenge.")
            }
        }
        let issuance = Issuance(
            client: client, grantID: code.grantID, subject: code.subject,
            resources: resources.isEmpty ? code.resources : resources)
        let granted = narrow(code.scope, subject: code.subject, resources: issuance.resources)
        let refreshToken =
            client.allowedGrants.contains(.refreshToken) ? mint(.refresh, issuance, scope: code.scope) : nil
        return tokenResponse(
            accessToken: mint(.access, issuance, scope: granted), scope: granted, client: client,
            refreshToken: refreshToken)
    }

    private func refresh(
        _ request: RecordedRequest, client: ClientRegistration, resources: [URL]
    ) throws -> HTTPResponse {
        guard let name = request.value("refresh_token"),
            var record = liveRecord(name, kind: .refresh), record.clientID == client.id
        else { throw Failure.oauth("invalid_grant", "The refresh token is invalid, expired or revoked.") }
        let (current, isReuse) = try resolveRotation(of: name, record: &record, client: client)
        var scope = record.scope
        if let text = request.value("scope") {
            scope = ScopeSet(parsing: text)
            guard scope.isSubset(of: record.scope) else {
                throw Failure.oauth("invalid_scope", "A refresh cannot widen the scope.")
            }
        }
        let denied = resources.contains(where: controls.isResourceUnauthorized)
        if denied && controls.refreshWithUnauthorizedResource == .invalidTarget400 {
            throw Failure.oauth("invalid_target", "The resource is not authorized.")
        }
        let granted =
            denied
            ? controls.narrowedScope : narrow(scope, subject: record.subject, resources: resources)
        let issuance = Issuance(
            client: client, grantID: record.grantID, subject: record.subject,
            resources: resources.isEmpty ? record.resources : resources, audience: record.audience)
        let rotated = rotate(current, isReuse: isReuse, issuance: issuance, scope: record.scope, client: client)
        return tokenResponse(
            accessToken: mint(.access, issuance, scope: granted), scope: granted, client: client, refreshToken: rotated)
    }

    /// Applies the rotation rules to a presented refresh token (RFC 9700 §4.14).
    ///
    /// A retired token is accepted again only inside the leeway and then resolves to the newest token of its
    /// chain (`record` is updated to it); otherwise the grant may be revoked and `invalid_grant` is thrown.
    func resolveRotation(
        of name: String, record: inout TokenRecord, client: ClientRegistration
    ) throws -> (current: String, isReuse: Bool) {
        var current = name
        guard client.rotatesRefreshTokens, record.successor != nil else { return (current, false) }
        guard let leeway = client.rotationLeeway, let rotatedAt = record.rotatedAt,
            now().timeIntervalSince(rotatedAt) <= leeway.window.timeInterval, record.reuseCount < leeway.maximumReuse
        else {
            if client.revokesGrantOnReuse { revokeGrant(record.grantID) }
            throw Failure.oauth("invalid_grant", "The refresh token was already used.")
        }
        tokens[name]?.reuseCount += 1
        while let next = record.successor, let successor = tokens[next] {
            (current, record) = (next, successor)
        }
        guard liveRecord(current, kind: .refresh) != nil else {
            throw Failure.oauth("invalid_grant", "The refresh token is invalid, expired or revoked.")
        }
        return (current, true)
    }

    /// Retires `current` and returns its successor, or returns `current` again for a leeway reuse.
    func rotate(_ current: String, isReuse: Bool, issuance: Issuance, scope: ScopeSet, client: ClientRegistration)
        -> String?
    {
        guard client.rotatesRefreshTokens else { return nil }
        if isReuse { return current }
        let successor = mint(.refresh, issuance, scope: scope)
        tokens[current]?.successor = successor
        tokens[current]?.rotatedAt = now()
        return successor
    }

    func handleRevocation(_ request: RecordedRequest) throws -> HTTPResponse {
        let client = try authenticate(request)
        if let name = request.value("token"), let record = tokens[name] {
            guard record.clientID == client.id else { throw Failure.oauth("unauthorized_client") }
            revoke(token: name)
        }
        return HTTPResponse(statusCode: 200)  // RFC 7009 §2.2: unknown tokens are not an error.
    }
}
