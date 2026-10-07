import Foundation
import PassportKit

struct AuthorizationCode {
    var clientID: String
    var grantID: Int
    var subject: String
    var redirectURI: String?
    var codeChallenge: String?
    var scope: ScopeSet
    var resources: [URL]
    var expiresAt: Date
    var isUsed = false
}

extension FakeAuthorizationServer {
    /// What the simulated user does at the authorization endpoint.
    public enum Decision: Sendable {
        /// Log in and consent.
        case approve
        /// Decline; the callback carries `error=access_denied` (RFC 6749 §4.1.2.1).
        case deny
    }

    /// Plays the user agent for an authorization request (RFC 6749 §4.1.1) and returns the callback URL.
    ///
    /// The callback carries `code` (or `error`), the request's `state` and, depending on
    /// ``Controls/issuerParameter``, `iss` (RFC 9207). Request problems that can be reported to the
    /// client become `error` callbacks; an unknown client or redirect URI throws ``ControlError``.
    public func authorizeInteractively(
        _ authorizationURL: URL, subject: String = "user-1", decision: Decision = .approve
    ) throws -> URL {
        // Form decoding, so that both `+` and `%20` mean a space, whichever a client chose.
        let query = URLComponents(url: authorizationURL, resolvingAgainstBaseURL: false)?.percentEncodedQuery ?? ""
        let items = (FormEncoding.decode(Data(query.utf8)) ?? []).map { (name: $0.0, value: $0.1) }
        func value(_ name: String) -> String? { items.first { $0.name == name }?.value }
        guard let client = value("client_id").flatMap({ clients[$0] }) else {
            throw ControlError(description: "The authorization request names an unknown client.")
        }
        let redirect = value("redirect_uri") ?? (client.redirectURIs.count == 1 ? client.redirectURIs[0] : nil)
        guard let redirect, client.redirectURIs.contains(where: { redirectMatches($0, redirect) }) else {
            throw ControlError(description: "The redirect URI is not registered.")
        }
        func callback(_ parameters: [(String, String)]) throws -> URL {
            var components = URLComponents(string: redirect)!
            var query = parameters + (value("state").map { [("state", $0)] } ?? [])
            switch controls.issuerParameter {
            case .issuer: query.append(("iss", Self.issuer.absoluteString))
            case .omitted: break
            case .value(let other): query.append(("iss", other))
            }
            components.queryItems = (components.queryItems ?? []) + query.map { URLQueryItem(name: $0.0, value: $0.1) }
            return components.url!
        }
        func failure(_ code: String) throws -> URL { try callback([("error", code)]) }

        guard value("response_type") == "code", client.allowedGrants.contains(.authorizationCode) else {
            return try failure("unauthorized_client")
        }
        let challenge = value("code_challenge")
        guard challenge != nil || client.secret != nil, challenge == nil || value("code_challenge_method") == "S256"
        else {
            return try failure("invalid_request")
        }
        let scope = ScopeSet(parsing: value("scope") ?? client.scope?.rawValue ?? "")
        if let allowed = client.scope, !scope.isSubset(of: allowed) { return try failure("invalid_scope") }
        let resources = items.filter { $0.name == "resource" }.compactMap { URL(string: $0.value) }
        guard decision == .approve else { return try failure("access_denied") }

        let code = nextIdentifier("code")
        codes[code] = AuthorizationCode(
            clientID: client.id, grantID: nextGrantID(), subject: subject, redirectURI: value("redirect_uri"),
            codeChallenge: challenge, scope: scope, resources: resources, expiresAt: now().addingTimeInterval(60))
        return try callback([("code", code)])
    }

    /// Exact match, except that loopback redirects may differ in port (RFC 8252 §7.3).
    private func redirectMatches(_ registered: String, _ requested: String) -> Bool {
        guard let registered = URLComponents(string: registered), var requested = URLComponents(string: requested)
        else {
            return false
        }
        if ["127.0.0.1", "localhost", "[::1]", "::1"].contains(registered.host ?? "") {
            requested.port = registered.port
        }
        return registered.url == requested.url
    }
}
