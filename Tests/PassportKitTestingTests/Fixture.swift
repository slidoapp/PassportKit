import Foundation
import PassportKit
import PassportKitTesting

/// RFC 7636 Appendix B example pair.
let pkceVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
let pkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

/// A parsed JSON response.
struct Reply {
    let response: HTTPResponse
    var status: Int { response.statusCode }
    var json: [String: Any] {
        (try? JSONSerialization.jsonObject(with: response.body)) as? [String: Any] ?? [:]
    }
    subscript(name: String) -> String? { json[name] as? String }
    var error: String? { self["error"] }
    var scope: ScopeSet? { self["scope"].map { ScopeSet(parsing: $0) } }
    var accessToken: String { self["access_token"] ?? "" }
    var refreshToken: String { self["refresh_token"] ?? "" }
}

enum Authentication {
    case publicClient(String)
    case basic(String, String)
    case post(String, String)
}

extension FakeAuthorizationServer.ClientRegistration {
    /// A public client that may use every user-facing grant.
    static func app(
        rotates: Bool = false, leeway: FakeAuthorizationServer.RotationLeeway? = nil,
        revokesGrantOnReuse: Bool = false, refreshLifetime: TimeInterval? = nil
    ) -> Self {
        Self(
            id: "app", allowedGrants: [.authorizationCode, .refreshToken, .deviceCode, .tokenExchange],
            scope: ["read", "write", "admin"], rotatesRefreshTokens: rotates, rotationLeeway: leeway,
            revokesGrantOnReuse: revokesGrantOnReuse, accessTokenLifetime: 900, refreshTokenLifetime: refreshLifetime)
    }

    /// A confidential client for `client_credentials`.
    static let service = Self(
        id: "service", secret: Secret("s3cret"), allowedGrants: [.clientCredentials], scope: ["read", "write"])
}

/// A server plus helpers that speak to it through raw requests.
struct Fixture {
    let server: FakeAuthorizationServer
    let wallClock = FixedWallClock()

    init(_ clients: [FakeAuthorizationServer.ClientRegistration] = [.app(), .service]) {
        server = FakeAuthorizationServer(clients: clients, wallClock: wallClock)
    }

    static let tokenURL = FakeAuthorizationServer.tokenEndpoint

    func post(_ url: URL, _ form: [(String, String)], as auth: Authentication = .publicClient("app")) async throws
        -> Reply
    {
        var form = form
        var headers: HTTPHeaders = ["Content-Type": "application/x-www-form-urlencoded"]
        switch auth {
        case .publicClient(let id): form.append(("client_id", id))
        case .post(let id, let secret): form += [("client_id", id), ("client_secret", secret)]
        case .basic(let id, let secret):
            headers["Authorization"] = "Basic " + Data("\(id):\(secret)".utf8).base64EncodedString()
        }
        let request = HTTPRequest(method: .post, url: url, headers: headers, body: FormEncoding.encode(form))
        return Reply(response: try await server.send(request))
    }

    func token(_ form: [(String, String)], as auth: Authentication = .publicClient("app")) async throws -> Reply {
        try await post(Self.tokenURL, form, as: auth)
    }

    func refresh(_ refreshToken: String, extra: [(String, String)] = []) async throws -> Reply {
        try await token([("grant_type", "refresh_token"), ("refresh_token", refreshToken)] + extra)
    }

    func get(_ url: URL, headers: HTTPHeaders = [:]) async throws -> HTTPResponse {
        try await server.send(HTTPRequest(method: .get, url: url, headers: headers))
    }

    /// Calls the protected resource with an optional Bearer token.
    func api(_ token: String?, path: String = "/v1/things") async throws -> HTTPResponse {
        let headers: HTTPHeaders = token.map { ["Authorization": "Bearer \($0)"] } ?? [:]
        return try await get(URL(string: "https://api.example.com" + path)!, headers: headers)
    }

    func authorizationURL(
        scope: String? = "read write", challenge: String? = pkceChallenge,
        redirect: String = "https://app.example.com/callback",
        extra: [(String, String)] = []
    ) -> URL {
        var components = URLComponents(
            url: FakeAuthorizationServer.authorizationEndpoint, resolvingAgainstBaseURL: false)!
        var items = [("response_type", "code"), ("client_id", "app"), ("redirect_uri", redirect), ("state", "st-1")]
        if let scope { items.append(("scope", scope)) }
        if let challenge { items += [("code_challenge", challenge), ("code_challenge_method", "S256")] }
        components.queryItems = (items + extra).map { URLQueryItem(name: $0.0, value: $0.1) }
        return components.url!
    }

    func callbackValue(_ name: String, in url: URL) -> String? {
        URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first { $0.name == name }?.value
    }

    /// Runs the authorization code flow with PKCE and returns the token response.
    func signIn(scope: String? = "read write", extra: [(String, String)] = []) async throws -> Reply {
        let callback = try await server.authorizeInteractively(authorizationURL(scope: scope))
        return try await token(
            [
                ("grant_type", "authorization_code"), ("code", callbackValue("code", in: callback) ?? ""),
                ("redirect_uri", "https://app.example.com/callback"), ("code_verifier", pkceVerifier),
            ] + extra)
    }

    func startDevice(scope: String = "read") async throws -> Reply {
        try await post(FakeAuthorizationServer.deviceAuthorizationEndpoint, [("scope", scope)])
    }

    func poll(_ deviceCode: String) async throws -> Reply {
        try await token([
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"), ("device_code", deviceCode),
        ])
    }
}
