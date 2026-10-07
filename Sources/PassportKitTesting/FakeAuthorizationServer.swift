import Foundation
import PassportKit

/// An in-process authorization server and protected resource, used as an ``HTTPTransport``.
///
/// It serves `https://as.example.com` (metadata, authorization, token, device authorization and
/// revocation endpoints; see ``FakeAuthorizationServer/issuer``) and `https://api.example.com/...`
/// (a resource that validates Bearer tokens). Clients are registered by configuration, behaviour is
/// scripted through ``configure(_:)``, and every request is recorded.
///
/// Tokens are opaque and deterministic (`access-1`, `refresh-2`, ...). Expiry follows the injected
/// ``WallClock``; per-request delays follow the injected `Clock`.
public actor FakeAuthorizationServer: HTTPTransport {
    /// The issuer identifier, `https://as.example.com`.
    public static let issuer = URL(string: "https://as.example.com")!
    /// The authorization endpoint, `/authorize`.
    public static let authorizationEndpoint = URL(string: "https://as.example.com/authorize")!
    /// The token endpoint, `/token`.
    public static let tokenEndpoint = URL(string: "https://as.example.com/token")!
    /// The device authorization endpoint (RFC 8628 §3.1), `/device_authorization`.
    public static let deviceAuthorizationEndpoint = URL(string: "https://as.example.com/device_authorization")!
    /// The revocation endpoint (RFC 7009), `/revoke`.
    public static let revocationEndpoint = URL(string: "https://as.example.com/revoke")!
    /// The base URL of the protected resource, `https://api.example.com`.
    public static let resourceBase = URL(string: "https://api.example.com")!

    /// A client registered with the server.
    public struct ClientRegistration: Sendable {
        /// The `client_id`.
        public var id: String
        /// The secret; `nil` makes a public client. Accepted through HTTP Basic or the request body.
        public var secret: Secret?
        /// The grant types the client may use.
        public var allowedGrants: Set<GrantType>
        /// The scopes the client may request; `nil` allows any.
        public var scope: ScopeSet?
        /// Whether a refresh issues a new refresh token and retires the old one (RFC 9700 §4.14).
        public var rotatesRefreshTokens: Bool
        /// How long a retired refresh token still works; `nil` means not at all.
        public var rotationLeeway: RotationLeeway?
        /// Whether presenting a retired refresh token outside the leeway revokes the whole grant.
        public var revokesGrantOnReuse: Bool
        /// Access token lifetime in seconds.
        public var accessTokenLifetime: TimeInterval
        /// Refresh token lifetime in seconds; `nil` means no expiry.
        public var refreshTokenLifetime: TimeInterval?
        /// The registered redirect URIs (loopback addresses match with any port, RFC 8252 §7.3).
        public var redirectURIs: [String]

        /// Creates a registration.
        public init(
            id: String,
            secret: Secret? = nil,
            allowedGrants: Set<GrantType> = [.authorizationCode, .refreshToken],
            scope: ScopeSet? = nil,
            rotatesRefreshTokens: Bool = false,
            rotationLeeway: RotationLeeway? = nil,
            revokesGrantOnReuse: Bool = false,
            accessTokenLifetime: TimeInterval = 3600,
            refreshTokenLifetime: TimeInterval? = nil,
            redirectURIs: [String] = ["https://app.example.com/callback"]
        ) {
            self.id = id
            self.secret = secret
            self.allowedGrants = allowedGrants
            self.scope = scope
            self.rotatesRefreshTokens = rotatesRefreshTokens
            self.rotationLeeway = rotationLeeway
            self.revokesGrantOnReuse = revokesGrantOnReuse
            self.accessTokenLifetime = accessTokenLifetime
            self.refreshTokenLifetime = refreshTokenLifetime
            self.redirectURIs = redirectURIs
        }
    }

    /// A window in which a rotated refresh token can be presented again, like servers that tolerate a retry.
    public struct RotationLeeway: Sendable {
        /// How long after rotation the old token still works.
        public var seconds: TimeInterval
        /// How many times it may be reused inside the window.
        public var maximumReuse: Int

        /// Creates a leeway, for example 120 seconds and one reuse.
        public init(seconds: TimeInterval, maximumReuse: Int) {
            self.seconds = seconds
            self.maximumReuse = maximumReuse
        }
    }

    /// What a refresh does when it names an unauthorized resource.
    public enum RefreshForUnauthorizedResource: Sendable {
        /// 200 with a fresh access token whose `scope` is ``Controls/narrowedScope``.
        case narrowScope200
        /// 400 `invalid_target` (RFC 8707 §2).
        case invalidTarget400
    }

    /// What a token exchange does when it names an unauthorized resource.
    public enum ExchangeForUnauthorizedResource: Sendable {
        /// 401 `access_denied`.
        case accessDenied401
        /// 200 with an access token whose `scope` is ``Controls/narrowedScope``.
        case narrowScope200
    }

    /// What the `iss` parameter of an authorization response (RFC 9207) carries.
    public enum IssuerParameter: Sendable {
        /// The real issuer.
        case issuer
        /// No `iss` parameter.
        case omitted
        /// A different value, to simulate a mix-up.
        case value(String)
    }

    /// Replaces the server's answer to one request.
    public struct ResponseOverride: Sendable {
        /// The response to send.
        public var response: HTTPResponse
        /// A transport failure to throw instead of answering.
        public var failure: (any Error)?
        /// How long to wait on the server's clock before answering.
        public var delay: Duration?

        /// Answers with a JSON `body` and `status`.
        public init(status: Int, body: String = "", headers: HTTPHeaders = [:], delay: Duration? = nil) {
            response = HTTPResponse(statusCode: status, headers: headers, body: Data(body.utf8))
            self.delay = delay
        }

        /// Fails the request with `failure`.
        public init(failure: any Error, delay: Duration? = nil) {
            response = HTTPResponse(statusCode: 500)
            self.failure = failure
            self.delay = delay
        }
    }

    /// Scriptable behaviour, changed with ``configure(_:)``.
    public struct Controls: Sendable {
        /// Returns the scopes a subject may hold for the requested resources; grants are narrowed to it.
        public var scopePolicy: (@Sendable (_ subject: String, _ resources: [URL]) -> ScopeSet)?
        /// Whether a resource is unauthorized for the subject (default: none).
        public var isResourceUnauthorized: @Sendable (URL) -> Bool = { _ in false }
        /// The refresh behaviour for unauthorized resources.
        public var refreshWithUnauthorizedResource = RefreshForUnauthorizedResource.narrowScope200
        /// The exchange behaviour for unauthorized resources.
        public var exchangeForUnauthorizedResource = ExchangeForUnauthorizedResource.accessDenied401
        /// The scope reported when a grant is narrowed because of an unauthorized resource.
        public var narrowedScope: ScopeSet = ["none"]
        /// The scope the protected resource requires; a token without it gets 403 `insufficient_scope`.
        public var requiredScope: ScopeSet?
        /// The `iss` parameter on authorization responses.
        public var issuerParameter = IssuerParameter.issuer
        /// The `issuer` member of the metadata document.
        public var advertisedIssuer = FakeAuthorizationServer.issuer.absoluteString
        /// Device code lifetime in seconds.
        public var deviceCodeLifetime: TimeInterval = 600
        /// The polling interval in seconds advertised to device clients.
        public var deviceInterval = 5
        /// Inspects each request before routing; a non-`nil` result replaces the normal answer.
        public var override: (@Sendable (RecordedRequest) -> ResponseOverride?)?
    }

    /// What the server knows about a token.
    public struct TokenDetails: Sendable {
        /// The user the token was issued for, or the client id for `client_credentials`.
        public var subject: String
        /// The client the token was issued to.
        public var clientID: String
        /// The scope the token carries.
        public var scope: ScopeSet
        /// The `resource` indicators the token was requested for.
        public var resources: [URL]
        /// The `audience` values the token was requested for (RFC 8693 §2.1).
        public var audience: [String]
    }

    /// Thrown when a test control is misused, for example approving an unknown user code.
    public struct ControlError: Error, CustomStringConvertible {
        /// What went wrong.
        public var description: String
    }

    /// The current behaviour switches.
    public private(set) var controls = Controls()
    /// Every request received, in order, including overridden ones.
    public private(set) var requests: [RecordedRequest] = []
    /// Every token that has been revoked.
    public private(set) var revoked: Set<String> = []

    let wallClock: any WallClock
    let clock: any Clock<Duration>
    var clients: [String: ClientRegistration]
    var tokens: [String: TokenRecord] = [:]
    var codes: [String: AuthorizationCode] = [:]
    var devices: [String: DeviceRecord] = [:]
    var grantCounts: [GrantType: Int] = [:]
    var slowDownsRemaining = 0
    var counter = 0

    /// Creates a server with registered `clients`.
    ///
    /// `wallClock` decides token expiry; `clock` times override delays and may be a ``ManualClock``.
    public init(
        clients: [ClientRegistration],
        wallClock: any WallClock = FixedWallClock(),
        clock: any Clock<Duration> = ContinuousClock()
    ) {
        self.clients = Dictionary(uniqueKeysWithValues: clients.map { ($0.id, $0) })
        self.wallClock = wallClock
        self.clock = clock
    }

    /// Changes the behaviour switches.
    public func configure(_ update: @Sendable (inout Controls) -> Void) { update(&controls) }

    /// The number of token endpoint requests that used `grantType`.
    public func requestCount(for grantType: GrantType) -> Int { grantCounts[grantType, default: 0] }

    /// The requests whose URL path is `path`.
    public func requests(to path: String) -> [RecordedRequest] { requests.filter { $0.path == path } }

    /// Revokes a token and, for a refresh token, every token of its grant (RFC 7009 §2.1).
    public func revoke(token: String) {
        guard let record = tokens[token] else { return }
        if record.kind == .refresh { revokeGrant(record.grantID) } else { revoked.insert(token) }
    }

    /// Makes a token expire now, by the injected wall clock's current time.
    public func expire(token: String) { tokens[token]?.expiresAt = wallClock.now() }

    /// What the server knows about `token`, or `nil` for an unknown one.
    public func details(of token: String) -> TokenDetails? {
        tokens[token].map {
            TokenDetails(
                subject: $0.subject, clientID: $0.clientID, scope: $0.scope, resources: $0.resources,
                audience: $0.audience)
        }
    }

    public func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        let recorded = RecordedRequest(request)
        requests.append(recorded)
        if recorded.path == "/token", let name = recorded.value("grant_type") {
            grantCounts[GrantType(rawValue: name), default: 0] += 1
        }
        if let override = controls.override?(recorded) {
            if let delay = override.delay { try await clock.sleep(for: delay) }
            if let failure = override.failure { throw failure }
            return override.response
        }
        do {
            switch request.url.host {
            case "as.example.com": return try routeAuthorizationServer(recorded)
            case "api.example.com": return try handleResource(recorded)
            default: throw URLError(.cannotFindHost)
            }
        } catch let failure as Failure {
            return failure.response
        }
    }

    private func routeAuthorizationServer(_ request: RecordedRequest) throws -> HTTPResponse {
        switch (request.method, request.path) {
        case (.get, "/.well-known/oauth-authorization-server"), (.get, "/.well-known/openid-configuration"):
            return metadata()
        case (.post, "/token"): return try handleToken(request)
        case (.post, "/device_authorization"): return try handleDeviceAuthorization(request)
        case (.post, "/revoke"): return try handleRevocation(request)
        case (_, "/token"), (_, "/device_authorization"), (_, "/revoke"),
            (_, "/.well-known/oauth-authorization-server"):
            throw Failure(response: HTTPResponse(statusCode: 405, headers: ["Allow": "POST"]))
        default: throw Failure(response: HTTPResponse(statusCode: 404))
        }
    }

    // MARK: Shared plumbing

    func nextIdentifier(_ prefix: String) -> String {
        counter += 1
        return "\(prefix)-\(counter)"
    }

    func nextGrantID() -> Int {
        counter += 1
        return counter
    }

    func now() -> Date { wallClock.now() }

    func revokeGrant(_ grantID: Int) {
        for (token, record) in tokens where record.grantID == grantID { revoked.insert(token) }
    }

    /// Returns the token's record when it is of `kind`, not revoked and not expired.
    func liveRecord(_ token: String?, kind: TokenRecord.Kind) -> TokenRecord? {
        guard let token, let record = tokens[token], record.kind == kind, !revoked.contains(token) else { return nil }
        if let expiresAt = record.expiresAt, expiresAt <= now() { return nil }
        return record
    }

    /// Authenticates the client of a token, device authorization or revocation request (RFC 6749 §2.3).
    func authenticate(_ request: RecordedRequest) throws -> ClientRegistration {
        var identifier = request.value("client_id")
        var secret = request.value("client_secret")
        var challenge: HTTPHeaders = [:]
        if let header = request.headers["Authorization"], header.lowercased().hasPrefix("basic ") {
            challenge = ["WWW-Authenticate": #"Basic realm="as""#]
            let decoded = Data(base64Encoded: String(header.dropFirst(6))).flatMap { String(data: $0, encoding: .utf8) }
            let parts = decoded?.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard let parts, parts.count == 2 else {
                throw Failure.oauth("invalid_client", status: 401, headers: challenge)
            }
            func decode(_ text: Substring) -> String? { FormEncoding.decode(Data("x=\(text)".utf8))?.first?.1 }
            identifier = decode(parts[0])
            secret = decode(parts[1])
        }
        guard let identifier, let client = clients[identifier], secret == client.secret?.reveal() else {
            throw Failure.oauth("invalid_client", status: 401, headers: challenge)
        }
        return client
    }

    /// Validates the requested scope against the client and returns what was asked for (or the default).
    func requestedScope(_ text: String?, client: ClientRegistration) throws -> ScopeSet {
        let requested = text.map { ScopeSet(parsing: $0) } ?? client.scope ?? []
        if let allowed = client.scope, !requested.isSubset(of: allowed) {
            throw Failure.oauth("invalid_scope", "The scope is not allowed for this client.")
        }
        return requested
    }

    /// Narrows `scope` to what the scope policy allows the subject for these resources.
    func narrow(_ scope: ScopeSet, subject: String, resources: [URL]) -> ScopeSet {
        guard let policy = controls.scopePolicy else { return scope }
        return ScopeSet(scope.scopes.intersection(policy(subject, resources).scopes))
    }

    func resources(of request: RecordedRequest) throws -> [URL] {
        try request.values("resource").map { text in
            guard let url = URL(string: text), url.scheme != nil, url.host != nil, !text.contains("#") else {
                throw Failure.oauth("invalid_target", "A resource must be an absolute URL without a fragment.")
            }
            return url
        }
    }
}

/// A response that ends request handling early.
struct Failure: Error {
    let response: HTTPResponse

    /// An RFC 6749 §5.2 error response.
    static func oauth(
        _ code: String, _ description: String? = nil, status: Int = 400, headers: HTTPHeaders = [:]
    ) -> Failure {
        var body = ["error": code]
        body["error_description"] = description
        return Failure(response: jsonResponse(status, body, headers: headers))
    }
}

func jsonResponse(_ status: Int, _ object: [String: Any], headers: HTTPHeaders = [:]) -> HTTPResponse {
    var headers = headers
    headers["Content-Type"] = "application/json"
    let body = (try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])) ?? Data()
    return HTTPResponse(statusCode: status, headers: headers, body: body)
}
