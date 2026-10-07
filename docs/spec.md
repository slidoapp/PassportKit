# PassportKit Specification

This is the implementation contract. Public names below are binding unless
an ADR changes them. Sketches show shape, not every initializer.

## 1. Scope

PassportKit is an OAuth 2.0 client library for native and server-side
Swift. It is built for one model in particular: **one root grant (a
refresh token) from which many audience- or resource-bound access tokens
are derived** (RFC 8707, RFC 8693), with refresh-token rotation.

In scope for 1.0:

| Area | Standard |
|---|---|
| Authorization code with PKCE (S256 only), `state`, `iss` validation | RFC 6749 §4.1, RFC 7636, RFC 9207, RFC 9700 |
| Native-app redirects: loopback, private-use scheme, claimed HTTPS | RFC 8252 |
| Device authorization grant | RFC 8628 |
| Refresh grant, client credentials grant | RFC 6749 §6, §4.4 |
| Token exchange | RFC 8693 |
| Resource indicators | RFC 8707 |
| Authorization server metadata | RFC 8414 |
| Token revocation | RFC 7009 |
| Bearer token usage and `WWW-Authenticate` challenges | RFC 6750, RFC 9110 §11.6 |

Out of scope for 1.0: implicit and password grants, OAuth 1.0, embedded
web views, dynamic client registration, OpenID Connect ID token
validation, introspection, DPoP, PAR, mTLS. The design leaves room for
DPoP and PAR (see §11).

## 2. Package

- `swift-tools-version: 6.2`, Swift 6 language mode, warnings as errors
  in CI.
- Platforms: macOS 14, iOS 17, tvOS 17, watchOS 10, visionOS 1. Linux for
  the core and testing modules.
- No third-party runtime dependencies.

| Product / target | Contents | Imports |
|---|---|---|
| `PassportKit` | Everything protocol-level: types, client, token manager, request authorizer, discovery, device flow, PKCE, challenge parsing, in-memory store | Foundation (FoundationNetworking on Linux); CryptoKit when available |
| `PassportKitApple` | `KeychainCredentialStore`, `WebAuthenticationSessionUserAgent` (`ASWebAuthenticationSession`), `LoopbackUserAgent` (Network framework listener + system browser) | `PassportKit`, Security, AuthenticationServices, Network, AppKit/UIKit |
| `PassportKitTesting` | `FakeAuthorizationServer`, `ManualClock`, `FixedWallClock`, `SequenceRandomSource`, `RecordingTransport` | `PassportKit` |

Test targets: `PassportKitTests` (unit), `ConformanceTests` (scenarios
against the fake server), `PassportKitAppleTests` (Apple only).

An executable target `passportkit-example` (not a product) demonstrates
the device flow and discovery against a real server; it takes all values
from command-line arguments.

## 3. Core value types

```swift
/// A credential value. `description`, `debugDescription` and reflection print "<redacted>".
public struct Secret: Sendable, Hashable, Codable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public init(_ value: String)
    public func reveal() -> String
}

/// Space-delimited, case-sensitive, order-insensitive scope set (RFC 6749 §3.3).
public struct ScopeSet: Sendable, Hashable, Codable, ExpressibleByArrayLiteral, CustomStringConvertible {
    public init(_ scopes: some Sequence<String>)
    public init(parsing value: String)          // splits on spaces, drops empty items
    public var scopes: Set<String> { get }
    public var rawValue: String { get }         // sorted, space-joined; deterministic
    public func contains(_ scope: String) -> Bool
    public func isSubset(of other: ScopeSet) -> Bool
}

/// Ordered parameters that may repeat; used for vendor extensions on every request.
public struct AdditionalParameters: Sendable, Hashable, ExpressibleByDictionaryLiteral {
    public private(set) var items: [(name: String, value: String)]   // stored as a Hashable pair struct internally
    public mutating func append(_ name: String, _ value: String)
}

/// Lossless JSON for unknown response members.
public enum JSONValue: Sendable, Hashable, Codable {
    case string(String), number(Double), bool(Bool), array([JSONValue]), object([String: JSONValue]), null
}

public struct GrantType: RawRepresentable, Sendable, Hashable, Codable {   // open set
    public static let authorizationCode, refreshToken, deviceCode, tokenExchange, clientCredentials: GrantType
}

public struct TokenTypeIdentifier: RawRepresentable, Sendable, Hashable, Codable {   // RFC 8693 §3, open set
    public static let accessToken, refreshToken, idToken, jwt: TokenTypeIdentifier
}
```

Injected seams (default implementations are the only code allowed to
touch system time and randomness):

```swift
public protocol WallClock: Sendable { func now() -> Date }
public struct SystemWallClock: WallClock {}
public protocol RandomSource: Sendable { func bytes(count: Int) -> [UInt8] }
public struct SystemRandomSource: RandomSource {}   // SystemRandomNumberGenerator (CSPRNG on all platforms)
```

Rules:

- Every token, code, verifier, device code and client secret in public
  API is a `Secret`, never a `String`.
- `AdditionalParameters` are appended after standard parameters. A name
  that collides with a parameter the library sets throws
  `PassportError` with code `.invalidConfiguration`.
- Resource indicators are `URL`s; they must be absolute and have no
  fragment (RFC 8707 §2), otherwise `.invalidConfiguration`.

## 4. HTTP

```swift
public struct HTTPRequest: Sendable, CustomStringConvertible {   // description redacts body and Authorization
    public var method: HTTPMethod
    public var url: URL
    public var headers: HTTPHeaders
    public var body: Data?
}
public struct HTTPResponse: Sendable { public var statusCode: Int; public var headers: HTTPHeaders; public var body: Data }
public struct HTTPHeaders: Sendable, Hashable, Sequence, ExpressibleByDictionaryLiteral {
    // case-insensitive names, preserves multiple values (multiple WWW-Authenticate lines)
    public subscript(name: String) -> String? { get set }   // first value
    public func values(for name: String) -> [String]
    public mutating func add(name: String, value: String)
}
public protocol HTTPTransport: Sendable {
    /// Throws only for transport failures; any HTTP status is a normal response.
    func send(_ request: HTTPRequest) async throws -> HTTPResponse
}
public struct URLSessionTransport: HTTPTransport {
    public init(configuration: URLSessionConfiguration = .ephemeral)
}
```

`URLSessionTransport`:
- does not follow redirects for `POST` requests;
- uses an ephemeral configuration without cookies or cache by default;
- caps response bodies at 1 MiB (`.invalidResponse` beyond that).

Form bodies follow RFC 6749 Appendix B: UTF-8, every character except
unreserved ones percent-encoded, space as `+`, `+` as `%2B`.

## 5. Configuration and client authentication

```swift
public struct Endpoints: Sendable, Hashable {
    public var authorization: URL?
    public var token: URL
    public var deviceAuthorization: URL?
    public var revocation: URL?
    public init(metadata: AuthorizationServerMetadata) throws   // throws if token endpoint missing
}

public enum ClientAuthentication: Sendable, Hashable {
    case none(clientID: String)                                       // public client: client_id in body
    case clientSecretPost(clientID: String, secret: Secret)
    case clientSecretBasic(clientID: String, secret: Secret)          // RFC 6749 §2.3.1: form-encode id and secret before base64
    public var clientID: String { get }
}

public struct ClientConfiguration: Sendable {
    public var endpoints: Endpoints
    public var authentication: ClientAuthentication
    public var issuer: URL?                          // used for RFC 9207 `iss` checks
    public var additionalHeaders: HTTPHeaders = [:] // sent on every request to the authorization server
    public var minimumTokenLifetime: Duration = .seconds(60)   // refresh earlier than this before expiry
    public var defaultTokenLifetime: Duration? = nil           // used when `expires_in` is missing; nil = treat as expired
}
```

HTTP `http` endpoints are rejected unless the host is a loopback address
(`localhost`, `127.0.0.1`, `::1`).

## 6. Errors

```swift
public struct PassportError: Error, Sendable, Equatable, CustomStringConvertible {
    public struct Code: RawRepresentable, Sendable, Hashable {   // open set; server codes preserved
        // RFC 6749 §5.2, RFC 8628 §3.5, RFC 8693 §2.2.2, RFC 8707 §2, RFC 6750 §3.1
        public static let invalidRequest, invalidClient, invalidGrant, unauthorizedClient,
            unsupportedGrantType, invalidScope, invalidTarget, accessDenied, expiredToken,
            authorizationPending, slowDown, temporarilyUnavailable, serverError,
            invalidToken, insufficientScope: Code
        // Client-side
        public static let invalidResponse, invalidConfiguration, stateMismatch, issuerMismatch,
            transportFailure, storageFailure, tokenRejected, notAuthenticated, userCancelled,
            timedOut, unauthorized: Code
    }
    public enum Recovery: Sendable, Hashable {
        case reauthenticate        // the root grant is gone
        case resourceDenied        // this resource/audience is not accessible; session intact
        case retryLater(after: Duration?)
        case fixConfiguration
        case none
    }
    public var code: Code
    public var recovery: Recovery
    public var statusCode: Int?
    public var errorDescription: String?    // server text, redacted and truncated to 200 characters; never used for logic
    public var errorURI: URL?
    public var underlying: (any Error & Sendable)?
}
```

Classification rules (tested exhaustively):

1. For any non-2xx response from the authorization server, parse the JSON
   body first. The `error` member decides the code; the HTTP status is
   only recorded. A 401 with `error=access_denied` is `.accessDenied`.
2. A non-JSON or malformed error body maps by status: 429 and 5xx to
   `.temporarilyUnavailable` with `.retryLater` (honour `Retry-After`
   seconds), anything else to `.invalidResponse`.
3. Recovery mapping:

| Code | Context | Recovery |
|---|---|---|
| `invalidGrant` | refresh grant, or refresh token as exchange subject | `.reauthenticate` |
| `invalidGrant` | other grants | `.none` |
| `accessDenied`, `invalidTarget`, `insufficientScope`, `tokenRejected` | any | `.resourceDenied` |
| `invalidClient`, `unauthorizedClient`, `unsupportedGrantType`, `invalidRequest`, `invalidScope`, `invalidConfiguration` | any | `.fixConfiguration` |
| `temporarilyUnavailable`, `serverError`, `transportFailure` | any | `.retryLater(after:)` |
| `expiredToken` | device flow | `.reauthenticate` |
| `accessDenied` | device flow or authorization response | `.none` (the user declined) |

Cancellation is not wrapped: `CancellationError` propagates unchanged.
User cancellation of a browser sheet is `.userCancelled`.

## 7. Token responses

```swift
public struct TokenResponse: Sendable, CustomStringConvertible {
    public var accessToken: Secret
    public var tokenType: String                    // compared case-insensitively
    public var expiresIn: Duration?
    public var refreshToken: Secret?
    public var idToken: Secret?
    public var scope: ScopeSet?                     // as returned; nil when omitted
    public var issuedTokenType: TokenTypeIdentifier?   // RFC 8693
    public var additionalFields: [String: JSONValue]   // every other member, e.g. vendor fields
}
```

Parsing tolerates `expires_in` as a number or numeric string, unknown
members, and `token_type` in any case. It rejects a 2xx response without
`access_token` or `token_type` (`.invalidResponse`). `token_type` is
not checked for exchanges whose `issued_token_type` is not an access
token (RFC 8693 §2.2.1 allows `N_A`).

The **granted scope** of a response is `scope` when present, otherwise
the requested scope (RFC 6749 §5.1). Narrower-than-requested scope is
not an error by itself.

## 8. `OAuthClient` — stateless protocol operations

```swift
public struct OAuthClient: Sendable {
    public init(configuration: ClientConfiguration,
                transport: any HTTPTransport = URLSessionTransport(),
                wallClock: any WallClock = SystemWallClock(),
                clock: any Clock<Duration> = ContinuousClock(),
                random: any RandomSource = SystemRandomSource(),
                observer: (any PassportObserver)? = nil)

    // RFC 6749 §6 (+ RFC 8707 resources)
    public func refresh(refreshToken: Secret, scope: ScopeSet? = nil, resources: [URL] = [],
                        additionalParameters: AdditionalParameters = [:]) async throws -> TokenResponse
    // RFC 6749 §4.4
    public func clientCredentials(scope: ScopeSet? = nil, resources: [URL] = [],
                                  additionalParameters: AdditionalParameters = [:]) async throws -> TokenResponse
    // RFC 8693
    public func exchange(_ request: TokenExchangeRequest) async throws -> TokenResponse
    // RFC 7009
    public func revoke(_ token: Secret, typeHint: TokenTypeHint? = nil) async throws
    // RFC 8628
    public func startDeviceAuthorization(scope: ScopeSet? = nil, resources: [URL] = [],
                                         additionalParameters: AdditionalParameters = [:]) async throws -> DeviceAuthorization
    public func completeDeviceAuthorization(_ authorization: DeviceAuthorization,
                                            additionalParameters: AdditionalParameters = [:]) async throws -> TokenResponse
    // RFC 6749 §4.1 + RFC 7636 + RFC 9207
    public func beginAuthorization(_ request: AuthorizationRequest) throws -> PendingAuthorization
    public func completeAuthorization(_ pending: PendingAuthorization, callbackURL: URL,
                                      additionalParameters: AdditionalParameters = [:]) async throws -> TokenResponse
    public func authorize(_ request: AuthorizationRequest, using userAgent: any UserAgent) async throws -> TokenResponse
    // Extension grants (e.g. vendor-specific): full error parsing and redaction
    public func requestToken(grantType: GrantType, parameters: AdditionalParameters) async throws -> TokenResponse
}

public struct TokenExchangeRequest: Sendable {
    public var subjectToken: Secret
    public var subjectTokenType: TokenTypeIdentifier
    public var actorToken: Secret?
    public var actorTokenType: TokenTypeIdentifier?
    public var requestedTokenType: TokenTypeIdentifier?
    public var audiences: [String] = []
    public var resources: [URL] = []
    public var scope: ScopeSet?
    public var additionalParameters: AdditionalParameters = [:]
}
public enum TokenTypeHint: String, Sendable { case accessToken = "access_token", refreshToken = "refresh_token" }
```

### Device authorization (RFC 8628)

```swift
public struct DeviceAuthorization: Sendable {
    public var userCode: String
    public var verificationURI: URL
    public var verificationURIComplete: URL?     // used verbatim; may already contain a query
    public var expiresAt: ContinuousClock.Instant
    public var interval: Duration                 // 5 s when omitted
    // internal: deviceCode (Secret)
}
```

Polling rules: wait `interval` before each request; on `slow_down` add
5 s permanently; on `authorization_pending` continue; on transport
errors, 429 and 5xx back off exponentially (doubling, capped at 30 s)
and reset to `interval` after the next server response; stop with
`.expiredToken` when the deadline passes without sending another
request; `access_denied` and `expired_token` are terminal; task
cancellation stops immediately. The library never opens a browser.

### Authorization code with PKCE

```swift
public struct AuthorizationRequest: Sendable {
    public var redirectURI: URL
    public var scope: ScopeSet?
    public var resources: [URL] = []
    public var loginHint: String?
    public var prompt: String?
    public var additionalParameters: AdditionalParameters = [:]
}
public struct PendingAuthorization: Sendable {
    public var url: URL                   // open in an external user agent
    public var redirectURI: URL
    // internal: state (Secret), codeVerifier (Secret), createdAt; expires after 10 minutes; single use
}
public protocol UserAgent: Sendable {
    /// Presents `url` and returns the callback URL that matched `redirectURI`.
    func present(_ url: URL, redirectURI: URL) async throws -> URL
}
```

`beginAuthorization`: 32 random bytes for `state` and the verifier
(base64url, no padding), `code_challenge_method=S256`. The request URL
is the authorization endpoint plus query parameters; existing query
items on the endpoint are preserved.

`completeAuthorization` checks, in order: callback matches `redirectURI`
(scheme, host, port, path); `state` matches (constant-time comparison);
`error` parameter (→ `PassportError` from the response, recovery `.none`
for `access_denied`); `iss` equals the configured issuer when either the
response carries `iss` or metadata requires it (RFC 9207); `code`
present; then redeems the code with the verifier and `redirect_uri`.
A `PendingAuthorization` can be completed once.

## 9. `TokenManager` — the session

One actor per signed-in root grant.

```swift
public actor TokenManager {
    public init(client: OAuthClient, store: any CredentialStore, account: CredentialAccount,
                acceptancePolicy: any TokenAcceptancePolicy = AcceptAnyToken())

    public func load() async throws -> Credential?                 // restores from the store
    public func signIn(with response: TokenResponse, requestedScope: ScopeSet?) async throws  // adopt a grant result
    public var credential: Credential? { get }

    public func accessToken(for target: TokenTarget = .default) async throws -> AccessToken
    public func invalidate(_ token: AccessToken)                    // after a 401 with this token
    public func exchangeRefreshToken(audience: String?, resources: [URL] = [], scope: ScopeSet? = nil,
                                     requestedTokenType: TokenTypeIdentifier = .refreshToken) async throws -> TokenResponse
    public func signOut(revoke: Bool = true) async -> SignOutResult

    public nonisolated var events: AsyncStream<SessionEvent> { get }   // multiple subscribers supported
}

public struct TokenTarget: Sendable, Hashable {
    public enum Method: Sendable, Hashable {
        case refreshGrant             // refresh_token grant with `resources` (narrowing, RFC 8707 §2.2)
        case exchangeAccessToken      // RFC 8693: exchange the default access token for one bound to `resources`/`audiences`
    }
    public var method: Method
    public var resources: [URL]
    public var audiences: [String]
    public var scope: ScopeSet?
    public static let `default`: TokenTarget      // refresh grant, no resources, no scope
}

public struct AccessToken: Sendable, Hashable, CustomStringConvertible {
    public var value: Secret
    public var tokenType: String
    public var expiresAt: Date?
    public var grantedScope: ScopeSet?
    public var target: TokenTarget
    public var generation: Int          // changes whenever the cached token for this target changes
    public var additionalFields: [String: JSONValue]
}

public struct Credential: Sendable, Codable, Hashable {
    public var clientID: String
    public var issuer: URL?
    public var refreshToken: Secret?
    public var idToken: Secret?
    public var grantedScope: ScopeSet?
    public var updatedAt: Date
    public var additionalFields: [String: JSONValue]
}
```

Invariants (each has a conformance test):

1. **One lane.** Every operation that sends the refresh token (refresh
   grant, refresh-token exchange, revocation of the refresh token) runs
   in one FIFO lane per manager and reads the refresh token when it
   starts, not when it is queued.
2. **Coalescing.** Concurrent `accessToken(for:)` calls for the same
   target share one in-flight operation. Different targets never receive
   each other's tokens.
3. **Persist before publish.** A rotated refresh token (any response
   carrying `refresh_token`, including token exchanges whose subject is
   the refresh token) is saved to the store before the access token is
   returned. If saving fails, the new credential is kept in memory, the
   token is returned, and `SessionEvent.storageFailed` is emitted.
4. **Acceptance.** Every issued access token goes through the
   `TokenAcceptancePolicy` before it is cached or returned. On
   rejection the token is discarded, the rotated refresh token from the
   same response is still persisted, the call throws `.tokenRejected`
   with `.resourceDenied`, and the session stays signed in.
5. **Session end.** Only `invalid_grant` (or `invalid_client` returned
   for the refresh token, via `.reauthenticate`) on a lane operation ends
   the session: the credential is deleted, `SessionEvent.signedOut` with
   reason `.refreshTokenRejected` is emitted, and subsequent calls throw
   `.notAuthenticated`.
6. **Generations.** `signOut`, `signIn` and session end increment the
   session generation. An operation that completes under an older
   generation discards its result and writes nothing.
7. **Cancellation.** Cancelling a caller only stops it waiting. A
   request that was already sent is allowed to finish and its result is
   persisted.
8. **Expiry.** A cached token is used while
   `expiresAt - minimumTokenLifetime > now`. Tokens without expiry use
   `defaultTokenLifetime`, or are refreshed on every use when nil.
   Exchanged tokens never outlive their subject token: the subject is
   refreshed first if it would expire within `minimumTokenLifetime`.
9. **Derived tokens.** `.exchangeAccessToken` targets obtain the
   default access token, exchange it (`subject_token_type` and
   `requested_token_type` = access token), and cache the result per
   target. A `refresh_token` in such a response is ignored: it is not the
   root grant.
10. **Invalidation.** `invalidate(token)` drops the cached token only if
   its `generation` is still current, so N concurrent 401s for the same
   token cause one refresh.

```swift
public protocol TokenAcceptancePolicy: Sendable {
    func evaluate(_ token: AccessToken, response: TokenResponse) async -> TokenAcceptance
}
public enum TokenAcceptance: Sendable { case accept; case reject(reason: String) }
public struct AcceptAnyToken: TokenAcceptancePolicy {}
/// Accepts a token for a target with resources only if at least one of `scopes` was granted.
public struct RequireAnyScope: TokenAcceptancePolicy {
    public init(_ scopes: ScopeSet, when predicate: @escaping @Sendable (TokenTarget) -> Bool = { !$0.resources.isEmpty })
}

public enum SessionEvent: Sendable, Equatable {
    case signedIn
    case refreshed(target: TokenTarget)
    case tokenRejected(target: TokenTarget, grantedScope: ScopeSet?)
    case storageFailed
    case signedOut(reason: SignOutReason)     // .userInitiated, .refreshTokenRejected
}
```

### Storage

```swift
public struct CredentialAccount: Sendable, Hashable { public var service: String; public var account: String }
public protocol CredentialStore: Sendable {
    func load(_ account: CredentialAccount) async throws -> Credential?
    func save(_ credential: Credential, for account: CredentialAccount) async throws
    func delete(_ account: CredentialAccount) async throws
}
public actor InMemoryCredentialStore: CredentialStore { ... }
```

The library has no default service or account names. Only the root
credential is persisted; access tokens stay in memory. Stored records
are versioned JSON (`{"version": 1, ...}`).

`TokenManager.load()` ignores (and does not delete) a stored credential
whose `clientID` or `issuer` differ from the configuration.

## 10. Using tokens: `RequestAuthorizer`

```swift
public struct RequestAuthorizer: Sendable {
    public init(manager: TokenManager)
    /// Adds `Authorization: Bearer <token>`. Throws if no token can be obtained; never returns an unsigned request.
    public func authorize(_ request: URLRequest, for target: TokenTarget = .default) async throws -> (URLRequest, AccessToken)
    public func authorize(_ request: HTTPRequest, for target: TokenTarget = .default) async throws -> (HTTPRequest, AccessToken)
    /// Decides what to do with a resource-server response for a request sent with `token`.
    public func evaluate(statusCode: Int, headers: HTTPHeaders, token: AccessToken, attempt: Int) async -> RetryDecision
    /// Convenience: authorize, send, evaluate, retry at most once.
    public func send(_ request: HTTPRequest, for target: TokenTarget = .default, using transport: any HTTPTransport) async throws -> HTTPResponse
}
public enum RetryDecision: Sendable, Equatable { case deliver; case retry; case fail(PassportError) }

public struct AuthenticationChallenge: Sendable, Hashable {
    public var scheme: String
    public var parameters: [String: String]   // lower-cased names
    public var token68: String?
    public static func parse(_ headerValues: [String]) -> [AuthenticationChallenge]
}
```

`evaluate` rules:

| Response | Decision |
|---|---|
| not 401 | `.deliver` (403 is never refreshed) |
| 401 with `Bearer error="insufficient_scope"` | `.fail(.insufficientScope)` |
| 401 with `error="invalid_token"` or no Bearer error, `attempt == 0` | invalidate `token`, `.retry` |
| 401, `attempt >= 1` | `.fail(.unauthorized, recovery: .resourceDenied)` |

## 11. Discovery and extension room

```swift
public struct AuthorizationServerMetadata: Sendable, Codable, Hashable {
    public var issuer: URL
    public var authorizationEndpoint: URL?
    public var tokenEndpoint: URL?
    public var deviceAuthorizationEndpoint: URL?
    public var revocationEndpoint: URL?
    public var codeChallengeMethodsSupported: [String]?
    public var grantTypesSupported: [String]?
    public var authorizationResponseIssParameterSupported: Bool?
    public var additionalFields: [String: JSONValue]
}
public enum IssuerValidation: Sendable { case strict; case expected(URL); case disabled }
public enum Discovery {
    /// RFC 8414 §3.1: inserts `/.well-known/oauth-authorization-server` between host and path.
    /// `.openIDConnect` appends `/.well-known/openid-configuration` instead.
    public static func fetchMetadata(issuer: URL, style: Style = .oauth, validation: IssuerValidation = .strict,
                                     transport: any HTTPTransport = URLSessionTransport()) async throws -> AuthorizationServerMetadata
    public enum Style: Sendable { case oauth, openIDConnect }
}
```

Metadata is a hint: PassportKit always sends PKCE S256, never refuses
public clients because `none` is not advertised, and never enforces
`grant_types_supported`.

DPoP and PAR are not implemented. `TokenResponse.tokenType` and
`AccessToken.tokenType` are kept as strings so a future proof-of-possession
scheme does not change public types.

## 12. Observability

```swift
public protocol PassportObserver: Sendable { func record(_ event: PassportEvent) }
public enum PassportEvent: Sendable {
    case request(endpoint: EndpointKind, grantType: GrantType?)
    case response(endpoint: EndpointKind, statusCode: Int, errorCode: String?, duration: Duration)
}
public enum EndpointKind: String, Sendable { case token, deviceAuthorization, revocation, metadata, resource }
```

Events carry no URLs with query strings, no bodies and no secrets.

## 13. Apple module

- `KeychainCredentialStore(accessGroup: String? = nil, accessibility: .afterFirstUnlockThisDeviceOnly, useDataProtectionKeychain: Bool = false)`:
  generic password items keyed by service/account; add-or-update without
  delete-then-add; versioned JSON payload; distinguishes "not found" from
  errors (`errSecInteractionNotAllowed` → `.storageFailure`, recovery
  `.retryLater`).
- `WebAuthenticationSessionUserAgent` (`@MainActor`): wraps
  `ASWebAuthenticationSession` with a presentation-anchor provider and
  `prefersEphemeralWebBrowserSession`; private-use-scheme callbacks on all
  supported versions, HTTPS callbacks where available; maps
  `canceledLogin` to `.userCancelled`.
- `LoopbackUserAgent`: `NWListener` bound to `127.0.0.1` on an ephemeral
  port; `redirectURI` in the request is rewritten with the actual port
  (RFC 8252 §7.3); accepts exactly one request whose path matches,
  answers with a short HTML page, closes; times out (default 5 minutes);
  opens the URL through an injected `@Sendable (URL) async -> Void`
  (default `NSWorkspace`/`UIApplication`).

## 14. Testing module

`FakeAuthorizationServer` is an `HTTPTransport` (actor-backed) that
implements the token, device authorization, revocation and metadata
endpoints well enough to run every flow, and is scriptable:

- clients with flags: public/confidential, rotation on/off, rotation
  leeway (seconds and reuse count, like real servers that allow one reuse
  within 120 s);
- per-request hooks to override responses (status, body, headers, delay);
- scope policy closure `(subject, requestedResources) -> ScopeSet` to
  simulate narrowed grants;
- toggles for the two behaviours seen in the wild: refresh with
  `resource` returning 200 with narrowed scope, and token exchange
  returning `401 access_denied` for a denied resource;
- device flow: approve, deny, or leave pending per device code; emits
  `slow_down` on demand;
- records every request with decoded form parameters.

`ManualClock` implements `Clock<Duration>`; `sleep` suspends until the
test advances time. `FixedWallClock` returns a settable `Date`.

## 15. Quality gates

- `make check` (format lint, build with warnings as errors, all tests)
  passes on macOS; the core and testing modules build and test on Linux.
- No `Date()`, `Task.sleep`, `URLSession.shared`, `UUID()` or random APIs
  in core outside the default `SystemWallClock`, `SystemRandomSource` and
  `URLSessionTransport` implementations (CI grep).
- Redaction canary test: a run of every flow with canary secrets finds no
  canary in any error description, event, `String(describing:)` or
  `String(reflecting:)` of public values.
- DocC comments on every public symbol.
