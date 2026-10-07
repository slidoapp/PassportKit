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
| `PassportKitApple` | `KeychainCredentialStore`, `WebAuthenticationSessionUserAgent` (`ASWebAuthenticationSession`), `LoopbackRedirectListener` and `LoopbackUserAgent` (Network framework listener + system browser) | `PassportKit`, Security, AuthenticationServices, Network, AppKit/UIKit |
| `PassportKitTesting` | `FakeAuthorizationServer`, `ManualClock`, `FixedWallClock`, `SequenceRandomSource`, `RecordingTransport` | `PassportKit` |

Test targets: `PassportKitTests` (unit), `PassportKitTestingTests` (the
fake server itself), `ConformanceTests` (scenarios against the fake
server, including the redaction canary), `IntegrationTests` (a local
open-source server, macOS, run by `make integration`) and
`PassportKitAppleTests` (Apple only).

An executable target `passportkit-example` (not a product) demonstrates
discovery, the device and loopback code flows and one refresh against a
real server; it takes all values from command-line arguments.

Each library has a DocC catalog (`Sources/<Target>/<Target>.docc`); the
`PassportKit` catalog holds the articles.

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
  that collides with a parameter the library sets, or with `client_id` or
  `client_secret` in any authentication mode (RFC 6749 §2.3: one method per
  request), throws `PassportError` with code `.invalidConfiguration`.
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
    public init(configuration: URLSessionConfiguration = .ephemeral,
                requestTimeout: Duration = .seconds(30), resourceTimeout: Duration = .seconds(60))
}
```

`URLSessionTransport`:
- does not follow redirects for `POST` requests, nor from HTTPS to HTTP;
- on a redirect that changes scheme, host or port, drops every request header
  except `Accept`, `Accept-Language` and `User-Agent`;
- uses an ephemeral configuration without cookies or cache by default;
- times out after 30 s without progress (`timeoutIntervalForRequest`) and
  60 s in total (`timeoutIntervalForResource`); both are initializer
  parameters and override the passed configuration. Device polling does not
  shorten a send to the remaining device lifetime: a poll started just before
  the deadline can overrun it by at most the resource timeout, and its answer
  is still used (shortening would cancel a request the server may already have
  acted on);
- returns a response that was complete when the caller cancelled, so a rotated
  refresh token is never lost;
- caps response bodies at 1 MiB (`.invalidResponse` beyond that).

`HTTPHeaders` descriptions and reflection show header names only.

Form bodies follow RFC 6749 Appendix B: UTF-8, every character except
unreserved ones percent-encoded, space as `+`, `+` as `%2B`.

## 5. Configuration and client authentication

```swift
public struct Endpoints: Sendable, Hashable {
    public var authorization: URL?
    public var token: URL
    public var deviceAuthorization: URL?
    public var revocation: URL?
    public init(metadata: AuthorizationServerMetadata) throws   // throws if the token endpoint is missing or an endpoint is not https
}

public struct ClientAuthentication: Sendable, Hashable {            // open: factories, not cases
    public static func publicClient(clientID: String) -> ClientAuthentication            // client_id in body
    public static func clientSecretPost(clientID: String, secret: Secret) -> ClientAuthentication
    public static func clientSecretBasic(clientID: String, secret: Secret) -> ClientAuthentication   // RFC 6749 §2.3.1: form-encode id and secret before base64
    public var clientID: String { get }
}
}

public struct ClientConfiguration: Sendable {
    public var endpoints: Endpoints
    public var authentication: ClientAuthentication
    public var issuer: URL?                          // used for RFC 9207 `iss` checks
    public var additionalHeaders: HTTPHeaders = [:] // sent on every request to the authorization server
    public var minimumTokenLifetime: Duration = .seconds(60)   // refresh earlier than this before expiry
    public var defaultTokenLifetime: Duration? = nil           // used when `expires_in` is missing; nil = treat as expired
    public var requiresIssuerInAuthorizationResponse: Bool = false   // RFC 9207 §2.4: a missing `iss` fails; needs `issuer`
    public init(metadata: AuthorizationServerMetadata, authentication: ClientAuthentication,
                additionalHeaders: HTTPHeaders = [:], minimumTokenLifetime: Duration = .seconds(60),
                defaultTokenLifetime: Duration? = nil) throws
}
```

`ClientConfiguration.init(metadata:authentication:…)` is the discovery path:
it takes the endpoints and `issuer` from the metadata and sets
`requiresIssuerInAuthorizationResponse` to
`metadata.authorizationResponseIssParameterSupported == true` (RFC 9207 §3),
then validates. Prefer it over assembling a configuration by hand so the
mix-up defence follows what the server advertises.

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
        case noAction
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
   body first. The `error` member decides the code, provided it is a
   well-formed RFC 6749 §5.2 value of at most 64 characters (else the body
   counts as malformed, rule 2). `error_uri` is kept only when `http(s)`; the HTTP status is
   only recorded. A 401 with `error=access_denied` is `.accessDenied`.
2. A non-JSON or malformed error body maps by status: 429 and 5xx to
   `.temporarilyUnavailable` with `.retryLater` (honour `Retry-After`, as
   delta-seconds or, relative to the injected wall clock, an HTTP-date; discovery has
   no wall clock and honours seconds only), anything else to `.invalidResponse`.
3. Recovery mapping:

| Code | Context | Recovery |
|---|---|---|
| `invalidGrant` | refresh grant, or refresh token as exchange subject | `.reauthenticate` |
| `invalidGrant` | other grants | `.noAction` |
| `accessDenied`, `invalidTarget`, `insufficientScope`, `tokenRejected` | any | `.resourceDenied` |
| `invalidClient`, `unauthorizedClient`, `unsupportedGrantType`, `invalidRequest`, `invalidScope`, `invalidConfiguration` | any | `.fixConfiguration` |
| `temporarilyUnavailable`, `serverError`, `transportFailure` | any | `.retryLater(after:)` |
| `expiredToken` | device flow | `.reauthenticate` |
| `accessDenied` | device flow or authorization response | `.noAction` (the user declined) |

Cancellation is not wrapped: `CancellationError` propagates unchanged.
User cancellation of a browser sheet is `.userCancelled`.

`errorDescription` is untrusted text. It loses control, line-separator and
invisible format characters, token-like runs of 24 or more characters
become `<redacted>`, and it is cut to 200 characters. In addition, every
credential the library sent in the request (refresh, subject, actor and
device codes, authorization code, PKCE verifier, client secret, the token of
a revocation, the bearer token of a resource request) is replaced by
`<redacted>` wherever it appears, however short it is, so a server that
repeats a request value cannot make the library print it. Values of fewer
than four characters are left alone.

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
token (RFC 8693 §2.2.1 allows `N_A`). A token exchange response must carry
`issued_token_type` (RFC 8693 §2.2.1), else `.invalidResponse`.

The **granted scope** of a response is `scope` when present, otherwise
the requested scope (RFC 6749 §5.1). Narrower-than-requested scope is
not an error by itself.

## 8. `OAuthClient` — stateless protocol operations

```swift
public struct OAuthClient: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// Throws `.invalidConfiguration` when an endpoint or the issuer is not `https` (or loopback `http`).
    public init(configuration: ClientConfiguration,
                transport: any HTTPTransport = URLSessionTransport(),
                wallClock: any WallClock = SystemWallClock(),
                clock: any Clock<Duration> = ContinuousClock(),
                random: any RandomSource = SystemRandomSource(),
                observer: (any PassportObserver)? = nil) throws
    public let configuration: ClientConfiguration
    public let wallClock: any WallClock

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
```

`description`, `debugDescription` and reflection of an `OAuthClient` show the
client ID and the token endpoint only, so a dump never reaches the injected
transport or observer.

```swift
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
public struct TokenTypeHint: RawRepresentable, Sendable, Hashable {   // open: RFC 7009 §4.1.2 registry
    public static let accessToken, refreshToken: TokenTypeHint     // "access_token", "refresh_token"
}
```

### Device authorization (RFC 8628)

```swift
public struct DeviceAuthorization: Sendable {
    public internal(set) var userCode: String
    public internal(set) var verificationURI: URL
    public internal(set) var verificationURIComplete: URL?     // used verbatim; may already contain a query
    public internal(set) var expiresIn: Duration                 // as granted; see ADR 0006
    public internal(set) var expiresAt: Date                     // for display only
    public var remainingLifetime: Duration { get } // measured on the injected clock
    public internal(set) var interval: Duration                  // 5 s when omitted
    // internal: deviceCode (Secret)
    // Public memberwise init for previews and UI tests (deviceCode: Secret, clock: defaults to ContinuousClock).
    public init(deviceCode: Secret, userCode: String, verificationURI: URL, verificationURIComplete: URL? = nil,
                expiresIn: Duration, expiresAt: Date, interval: Duration = .seconds(5),
                clock: any Clock<Duration> = ContinuousClock())
}
```

The start response must have an `https` (or loopback `http`) verification URI,
else `.invalidResponse`; an insecure `verification_uri_complete` is dropped.
`verification_url` is accepted as an interoperability alias of
`verification_uri` (some providers shipped it before RFC 8628 settled on
`_uri`). An `interval` above one hour is `.invalidResponse`; `slow_down`
stops increasing the interval at one hour; `expires_in` is clamped to about
100 years. These bounds keep `Duration` conversions from trapping on hostile
numbers.

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
    public struct Prompt: RawRepresentable, Sendable, Hashable {   // open; OIDC Core §3.1.2.1
        public static let noInteraction, login, consent, selectAccount: Prompt   // "none", "login", "consent", "select_account"
    }
    public var redirectURI: URL
    public var scope: ScopeSet?
    public var resources: [URL] = []
    public var loginHint: String?
    public var prompt: [Prompt] = []      // sent as one space-delimited `prompt` parameter, in order
    public var additionalParameters: AdditionalParameters = [:]
    public var lifetime: Duration = .seconds(600)   // how long the user has; must be positive
}
public struct PendingAuthorization: Sendable, CustomStringConvertible {
    public let url: URL                   // open in an external user agent
    public let redirectURI: URL
    // internal: state (Secret), codeVerifier (Secret), stopwatch; expires after `AuthorizationRequest.lifetime`; single use
}
public protocol UserAgent: Sendable {
    /// Presents `url` and returns the callback URL that matched `redirectURI`.
    func present(_ url: URL, redirectURI: URL) async throws -> URL
}
```

`beginAuthorization`: 32 random bytes each for `state` and the verifier
(base64url, no padding; `state` is drawn first), `code_challenge_method=S256`.
The request URL is the authorization endpoint plus, in order, `response_type`,
`client_id`, `redirect_uri`, `state`, `code_challenge`,
`code_challenge_method`, `scope`, repeated `resource`, `login_hint`,
`prompt` and the additional parameters. Existing query items on the endpoint
are preserved; one that the request also sets is `.invalidConfiguration`, as
are a missing authorization endpoint and a redirect URI that is relative, has a
fragment, or is `http` on a non-loopback host (RFC 8252 §7.3, §8.3). A loopback
redirect URI carries the actual port; the callback is compared with it.

`completeAuthorization` checks, in order:

1. the pending authorization was not completed before (`.invalidConfiguration`)
   and has not expired (`.timedOut`, recovery `.reauthenticate`);
2. the callback matches `redirectURI` in scheme and host (case-insensitive),
   port (default ports implied) and path (exact), else `.invalidResponse`; a
   callback with userinfo never matches, and a query on the registered redirect
   URI must appear unchanged in the callback; the
   response is read from the query only, and a repeated response parameter or
   malformed encoding is `.invalidResponse`;
3. `state` matches (constant-time comparison), else `.stateMismatch`;
4. `iss` equals the configured issuer by exact string comparison, else
   `.issuerMismatch` (RFC 9207 §2.4). A missing `iss` fails only when
   `requiresIssuerInAuthorizationResponse` is set; with no issuer configured a
   response `iss` is accepted unchecked. This runs before step 5 because RFC
   9207 §2.4 requires the check for error responses too;
5. an `error` parameter becomes a `PassportError` through the authorization
   response context (recovery `.noAction` for `access_denied`);
6. `code` present, else `.invalidResponse`;

then it redeems the code with `grant_type`, `code`, `redirect_uri`,
`code_verifier`, the request's `resource` indicators (RFC 8707 §2.2) and
client authentication. An authorization `error` that is not a well-formed
RFC 6749 §4.1.2.1 value (at most 64 characters) is `.invalidResponse`;
`error_uri` keeps only `http(s)`.

A `PendingAuthorization` is single use. Copies share one flag, which is claimed
once the callback passes the `state` check: from then on any further
completion, including after a failed redemption or a server error response,
throws `.invalidConfiguration`. A callback rejected earlier (wrong redirect or
`state`) does not consume it, so a stray request to a loopback listener cannot
cancel the flow. Expiry is measured on the client's injected clock (ADR 0006).
`description` shows only the redirect target and age.

## 9. `TokenManager` — the session

One actor per signed-in root grant.

```swift
public actor TokenManager {
    public init(client: OAuthClient, store: any CredentialStore, account: CredentialAccount,
                acceptancePolicy: any TokenAcceptancePolicy = AcceptAnyToken(),
                acceptancePolicyTimeLimit: Duration = .seconds(10),    // no answer in time = rejection
                rejectedTokenCacheDuration: Duration = .seconds(30))   // .zero: ask the server every time

    public func load() async throws -> Credential?                 // restores from the store
    public func signIn(with response: TokenResponse, requestedScope: ScopeSet? = nil) async throws  // adopt a grant result; throws .tokenRejected if the policy rejects its access token (the session still exists)
    public var credential: Credential? { get }

    public func accessToken(for target: TokenTarget = .default) async throws -> AccessToken
    public func invalidate(_ token: AccessToken)                    // after a 401 with this token
    public func exchangeRefreshToken(audience: String?, resources: [URL] = [], scope: ScopeSet? = nil,
                                     requestedTokenType: TokenTypeIdentifier = .refreshToken) async throws -> TokenResponse
    public func signOut(revoke: Bool = true) async -> SignOutResult

    public nonisolated var events: AsyncStream<SessionEvent> { get }   // multiple subscribers supported
}

public struct TokenTarget: Sendable, Hashable {   // == and hash: derivation, scope and the SETS of resources and audiences
    public struct Derivation: Sendable, Hashable {   // open
        public static let refreshGrant: Derivation   // refresh_token grant with `resources` (narrowing, RFC 8707 §2.2)
        public static let tokenExchange: Derivation  // RFC 8693: exchange the default access token for one bound to `resources`/`audiences`
    }
    public var derivation: Derivation
    public var resources: [URL]
    public var audiences: [String]
    public var scope: ScopeSet?
    public static let `default`: TokenTarget      // refresh grant, no resources, no scope
    public static func refreshGrant(resources: [URL] = [], scope: ScopeSet? = nil) -> TokenTarget
    public static func exchange(resources: [URL] = [], audiences: [String] = [], scope: ScopeSet? = nil) -> TokenTarget
    // The memberwise initializer is `package`: the factories cover every valid combination.
}

public struct AccessToken: Sendable, Hashable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {   // descriptions never show values
    public var value: Secret
    public var tokenType: String
    public var expiresAt: Date?
    public var grantedScope: ScopeSet?
    public var target: TokenTarget
    public internal(set) var generation: Int   // changes whenever the cached token for this target changes
    public var additionalFields: [String: JSONValue]
    // The initializer is `package`: tokens come from the manager.
}

public struct Credential: Sendable, Codable, Hashable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {   // descriptions never show values
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
   in one FIFO lane per session and reads the refresh token when it
   starts, not when it is queued. A new session gets a new lane, so a
   request of an ended session that never answers cannot hold up the
   next one. A revocation takes its turn on the lane of the session it
   ends and sends the newest refresh token of that session: a request
   that was already in flight when the user signed out, and rotated the
   token, hands the new token over (ADR 0007).
2. **Coalescing.** Concurrent `accessToken(for:)` calls for the same
   target share one in-flight operation. Different targets never receive
   each other's tokens. Targets are equal when method, scope and the
   sets of resources and audiences are equal; order and repetition of
   resources and audiences do not matter. A nil scope and an empty scope
   differ. `signIn` registers the operation for the default target
   before it suspends, so callers during its save and policy check join
   it instead of refreshing.
3. **Persist before publish.** A rotated refresh token (any response
   carrying `refresh_token`, including token exchanges whose subject is
   the refresh token) is saved to the store before the access token is
   returned. If saving fails, the new credential is kept in memory, the
   token is returned, and `SessionEvent.storageFailed` is emitted.
   Saves and deletes of the stored credential are applied one after the
   other in the order the manager decided them, whatever the store's
   speed, so a late save never undoes a sign-out. If a delete fails the
   stored credential survives and `load()` would restore it:
   `SignOutResult.isStoredCredentialDeleted` is false and
   `.storageFailed` is emitted.
4. **Acceptance.** Every issued access token goes through the
   `TokenAcceptancePolicy` before it is cached or returned. The policy
   has `acceptancePolicyTimeLimit` to answer (the default policy is not
   timed); no answer is a rejection. On rejection the token is
   discarded, the rotated refresh token from the same response is still
   persisted, the call throws `.tokenRejected` with `.resourceDenied`,
   and the session stays signed in. The rejection is remembered per
   target for `rejectedTokenCacheDuration`: asking again within that time
   throws the same error without a request and without a second
   `.tokenRejected` event, so a retrying caller cannot make the manager
   rotate the refresh token in a loop. A sign-in, a sign-out, the end of
   the session and `invalidate(_:)` for the target forget it.
5. **Session end.** Only an error with recovery `.reauthenticate` on a
   lane operation ends the session, which in practice means `invalid_grant`
   for the refresh token, whether the refresh was narrowed to resources or
   a scope or not (RFC 6749 §5.2 defines `invalid_grant` as a problem with
   the grant; `invalid_client` is `.fixConfiguration`, `invalid_scope` is
   `.fixConfiguration` and `invalid_target` is `.resourceDenied`, none of
   them ends it). The credential is deleted, `SessionEvent.signedOut`
   with reason `.refreshTokenRejected` is emitted, and subsequent calls
   throw `.notAuthenticated` (recovery `.reauthenticate`). An
   `invalid_grant` that arrives after the session was replaced is ignored
   (invariant 6). A grant that issued no refresh token ends the same way,
   with reason `.expiredWithoutRefreshToken`, when its access token has
   expired and a new one is needed.
6. **Generations.** `signOut`, `signIn` and session end increment the
   session generation. An operation that completes under an older
   generation discards its result and writes nothing. A caller that was
   waiting for such an operation asks again once on the session that
   exists now, if there is one, instead of failing; with none it throws
   `.notAuthenticated`. `.signedOut` and `.signedIn` are emitted before
   the manager first suspends, so their order is the order of the calls.
7. **Cancellation.** Cancelling a caller only stops it waiting. A
   request that was already sent is allowed to finish and its result is
   persisted. A caller that is cancelled before it starts never starts
   one. A cancelled `signOut` clears the session and reports the
   revocation as `.cancelled`.
8. **Expiry.** A cached token is used while
   `expiresAt - minimumTokenLifetime > now`. Tokens without expiry use
   `defaultTokenLifetime`, or are refreshed on every use when nil.
   Exchanged tokens never outlive their subject token: the subject is
   refreshed first if it would expire within `minimumTokenLifetime`.
9. **Derived tokens.** `.exchangeAccessToken` targets obtain the
   default access token, exchange it (`subject_token_type` and
   `requested_token_type` = access token), and cache the result per
   target. A `refresh_token` in such a response is ignored: it is not the
   root grant. An `invalid_grant` from the exchange drops the cached default
   token it used (the server no longer accepts it) and leaves the session
   intact.
10. **Invalidation.** `invalidate(token)` drops the cached token only if
   its `generation` is still current, so N concurrent 401s for the same
   token cause one refresh.

`exchangeRefreshToken` is not coalesced (each call sends one request) and its
result is not cached or run through the acceptance policy: the issued token is
usually a refresh token for another audience and belongs to the application.
Its `refresh_token`, the rotated subject, is persisted. Revocation in
`signOut` also takes a lane turn, reserved before `signOut` suspends, so it
queues behind operations already sending the old token; the request and the
wait for it are each limited to 5 s on the client's clock. A time limit gives up
on an operation that ignores cancellation, which then runs on in the background.

```swift
public protocol TokenAcceptancePolicy: Sendable {
    func evaluate(_ context: TokenAcceptanceContext) async -> TokenAcceptance
}
public struct TokenAcceptanceContext: Sendable {   // evolvable; the initializer is `package`
    public var token: AccessToken
    public var response: TokenResponse
    public var target: TokenTarget { get }          // token.target
}
public enum TokenAcceptance: Sendable { case accept; case reject(reason: String) }
/// The default: accepts everything, scope narrowing included (documented hazard on `TokenManager.init`).
public struct AcceptAnyToken: TokenAcceptancePolicy {}
/// Which targets a policy applies to. Open struct.
public struct TargetSelector: Sendable {
    public static let all: TargetSelector
    public static let withResources: TargetSelector
    public static func matching(_ predicate: @escaping @Sendable (TokenTarget) -> Bool) -> TargetSelector
    public func isSelected(_ target: TokenTarget) -> Bool
}
/// Accepts a token for a selected target (default: targets with resources) only if at least one of `scopes` was granted.
public struct RequireAnyScope: TokenAcceptancePolicy {
    public init(_ scopes: ScopeSet, forTargets targets: TargetSelector = .withResources)
}
/// A policy from a closure: `acceptancePolicy: .custom { context in ... }`.
public struct ClosureTokenAcceptancePolicy: TokenAcceptancePolicy {
    public init(_ body: @escaping @Sendable (TokenAcceptanceContext) async -> TokenAcceptance)
}
extension TokenAcceptancePolicy where Self == ClosureTokenAcceptancePolicy {
    public static func custom(_ body: @escaping @Sendable (TokenAcceptanceContext) async -> TokenAcceptance) -> ClosureTokenAcceptancePolicy
}

public enum SignOutReason: Sendable, Hashable { case userInitiated, refreshTokenRejected, expiredWithoutRefreshToken }
public struct SignOutResult: Sendable, Equatable {
    public enum Revocation: Sendable, Equatable { case skipped, revoked, failed(PassportError), timedOut, cancelled }
    public var isStoredCredentialDeleted: Bool     // memory is always cleared
    public var revocation: Revocation              // .skipped: not requested, no refresh token or no revocation endpoint
}

public enum SessionEvent: Sendable, Equatable {
    case signedIn
    case refreshed(target: TokenTarget)
    case tokenRejected(target: TokenTarget, grantedScope: ScopeSet?)
    case storageFailed
    case signedOut(reason: SignOutReason)     // .userInitiated, .refreshTokenRejected, .expiredWithoutRefreshToken
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
public actor InMemoryCredentialStore: CredentialStore {
    public init(credentials: [CredentialAccount: Credential] = [:])
    public func failNextSaves(_ count: Int = 1)       // injected save failures for tests
}
/// Versioned JSON for stores that write bytes: the credential's members plus `"version": 1`.
public enum CredentialCoding {
    public static func encode(_ credential: Credential) throws -> Data
    public static func decode(_ data: Data) throws -> Credential   // .storageFailure for malformed data or an unknown version
}
```

The library has no default service or account names. Only the root
credential is persisted; access tokens stay in memory. Stored records
are versioned JSON (`{"version": 1, ...}`).

`TokenManager.load()` ignores (and does not delete) a stored credential
whose `clientID` or `issuer` differ from the configuration. It does nothing
when a session is already active. `accessToken(for:)` does not load: with no
session it throws `.notAuthenticated`.

`events` returns a new stream per access, delivers events from then on (no
replay) and finishes when the manager is released (sign-out does not finish
it: the manager can sign in again). A stream buffers the newest 64 events it
has not yielded; older ones are dropped. `OAuthClient.configuration`
and `OAuthClient.wallClock` are public read-only properties.

## 10. Using tokens: `RequestAuthorizer`

```swift
public struct RequestAuthorizer: Sendable {
    public init(manager: TokenManager, transport: any HTTPTransport = URLSessionTransport())
    /// Adds `Authorization: Bearer <token>`. Throws if no token can be obtained; never returns an unsigned request.
    public func sign(_ request: URLRequest, for target: TokenTarget = .default) async throws -> (URLRequest, AccessToken)
    public func sign(_ request: HTTPRequest, for target: TokenTarget = .default) async throws -> (HTTPRequest, AccessToken)
    /// Decides what to do with a resource-server response for a request sent with `token`.
    public func evaluate(statusCode: Int, headers: HTTPHeaders, token: AccessToken, attempt: Int) async -> RetryDecision
    /// Convenience: sign, send on the transport given at creation, evaluate, retry at most once.
    public func send(_ request: HTTPRequest, for target: TokenTarget = .default) async throws -> HTTPResponse
    /// The same for `URLSession`; the session is required, the library never uses `URLSession.shared`.
    public func data(for request: URLRequest, target: TokenTarget = .default, session: URLSession) async throws -> (Data, HTTPURLResponse)
}
public enum RetryDecision: Sendable, Equatable { case deliver; case retry; case fail(PassportError) }

public struct AuthenticationChallenge: Sendable, Hashable {
    public var scheme: String
    public var parameters: [String: String]   // lower-cased names
    public var token68: String?
    public init(scheme: String, parameters: [String: String] = [:], token68: String? = nil)
    public static func parse(_ headerValues: [String]) -> [AuthenticationChallenge]
}
```

`parse` takes every `WWW-Authenticate` line (RFC 9110 §11.6.1): each line is a
comma-separated list of challenges, so one line may hold several. Scheme and
parameter names are case-insensitive and stored lower-cased (the scheme too, so
`DPoP` is `"dpop"`). Parameter values are tokens or quoted strings; commas
inside quotes do not split and `\` escapes the next character. `Negotiate abc==`
is the `token68` form. A repeated parameter name keeps its first value. Parsing
is lenient and total: malformed parts are skipped and input that is not a
challenge yields an empty array.

`evaluate` rules:

| Response | Decision |
|---|---|
| not 401 | `.deliver` (403 is never refreshed) |
| 401 with `Bearer error="insufficient_scope"` | `.fail(.insufficientScope)` |
| 401 with `error="invalid_token"` or no Bearer error, `attempt == 0` | invalidate `token`, `.retry` |
| 401, `attempt >= 1` | `.fail(.unauthorized, recovery: .resourceDenied)` |
| 401 at `attempt == 0` with any other Bearer error (`invalid_request`) | `.deliver` |

`authorize` throws `.invalidConfiguration` for a URL that is neither `https`
nor `http` on a loopback host, before asking for a token. It also throws
`.invalidConfiguration`, after obtaining the token and before anything is
sent, when `AccessToken.tokenType` is not `Bearer` (compared
case-insensitively): a sender-constrained type such as `DPoP` needs a proof
this authorizer cannot make, and a token must never be sent as a bearer
credential it was not issued as. The session is not affected. `send` and
`data(for:target:session:)` inherit both rules.

The `error_description` of an `insufficient_scope` challenge goes through the
same description rules as server errors (see §6) and has the bearer token
removed.

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
                                     transport: any HTTPTransport = URLSessionTransport(),
                                     observer: (any PassportObserver)? = nil,
                                     clock: any Clock<Duration> = ContinuousClock()) async throws -> AuthorizationServerMetadata
    public enum Style: Sendable { case oauth, openIDConnect }
}
```

Metadata keys are the RFC's snake_case names; members the type does not model
are kept in `additionalFields` and re-encoded. `fetchMetadata` reports
`.request`, `.response` and `.transportFailure` events with
`EndpointKind.metadata` to the observer, timed on `clock`. It sends `GET` with
`Accept: application/json`; terminating slashes of the issuer path are removed
before the well-known segment is added (`https://as.example.com/t/` gives
`https://as.example.com/.well-known/oauth-authorization-server/t`). The issuer
must be `https` (or loopback `http`) without query, fragment or userinfo
(`.invalidConfiguration`). Non-2xx responses are classified as for any server
error; a body that is not a JSON object with an `issuer` and well-formed known
members is `.invalidResponse`. `.strict` requires the metadata `issuer` to be
identical to the requested issuer (RFC 8414 §3.3): a string comparison, so a
trailing slash difference is a mismatch (`.issuerMismatch`); `.expected(url)`
compares with `url` instead; `.disabled` skips the check.

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
    case transportFailure(endpoint: EndpointKind, grantType: GrantType?, duration: Duration)
}
public struct EndpointKind: RawRepresentable, Sendable, Hashable {   // open
    public static let token, deviceAuthorization, revocation, metadata, resource: EndpointKind
}
```

Every `.request` is followed by exactly one `.response` or one
`.transportFailure` (no HTTP response: connection, TLS, timeout or task
cancellation). Events carry no URLs with query strings, no bodies and no
secrets.

## 13. Apple module

- `KeychainCredentialStore(accessGroup: String? = nil, accessibility: Accessibility = .afterFirstUnlockThisDeviceOnly, useDataProtectionKeychain: Bool = false, decodeLegacy: (@Sendable (Data) -> Credential?)? = nil)`:
  generic password items, `kSecAttrService` = `account.service`,
  `kSecAttrAccount` = `account.account`; versioned JSON payload
  (`CredentialCoding`). `save` is `SecItemUpdate`, then `SecItemAdd` on
  `errSecItemNotFound`, then one more update on `errSecDuplicateItem`
  (never delete-then-add). `load` returns `nil` for `errSecItemNotFound`;
  an undecodable payload and any other status are `.storageFailure` (the
  status number in the description, never item data);
  `errSecInteractionNotAllowed` (device locked) has recovery
  `.retryLater(after: nil)`. `delete` treats "not found" as success.
  Items are never synchronizable (`kSecAttrSynchronizable` is `false`, no
  option): a refresh token must not sync between devices.
  `useDataProtectionKeychain` maps to `kSecUseDataProtectionKeychain` on
  macOS and is ignored elsewhere; `accessibility` applies on iOS-family
  platforms and the macOS data protection keychain only. Calls block, so
  each runs on a private serial `DispatchQueue` bridged with a
  continuation. `decodeLegacy` is the migration hook: it is called only
  when versioned decoding fails, and a credential it returns is written
  back in the current format.
- `WebAuthenticationSessionUserAgent` (`@MainActor`): wraps
  `ASWebAuthenticationSession` with a presentation-anchor provider and
  `prefersEphemeralWebBrowserSession`; private-use-scheme callbacks on all
  supported versions, HTTPS callbacks where available; maps
  `canceledLogin` to `.userCancelled`.
- `LoopbackRedirectListener`: `static func start(path: String = "/callback", clock:)`
  binds an `NWListener` to `127.0.0.1` on an ephemeral port and returns
  once it is ready; `redirectURI` carries the real port (RFC 8252 §7.3).
  `waitForCallback(timeout:)` accepts requests whose path matches (others
  get 404), answers with a short HTML page without echoing the query,
  closes, and returns the full redirect URL; it throws `.timedOut`. The
  listener is started first so that its `redirectURI` goes into the
  `AuthorizationRequest`.
- `LoopbackUserAgent(listener:timeout:openURL:)`: a `UserAgent` for a
  running listener; opens the URL through an injected
  `@Sendable (URL) async throws -> Void` (default `NSWorkspace` /
  `UIApplication`), then `waitForCallback(timeout:)` (default 5 minutes).
  It rejects a request whose `redirectURI` is not the listener's.

## 14. Testing module

`FakeAuthorizationServer` is an `HTTPTransport` (actor-backed) that
implements the token, device authorization, revocation and metadata
endpoints well enough to run every flow, and is scriptable:

- clients with flags: public/confidential, rotation on/off, rotation
  leeway (seconds and reuse count, like real servers that allow one reuse
  within 120 s);
- per-request hooks to override responses (status, body, headers, delay) and to
  delay the answer of a request the server has already handled (`responseDelay`);
- token exchange with a refresh token subject spends and rotates it like a
  refresh grant, and `requested_token_type` = refresh token issues a refresh token;
- scope policy closure `(subject, requestedResources) -> ScopeSet` to
  simulate narrowed grants;
- toggles for the two behaviours seen in the wild: refresh with
  `resource` returning 200 with narrowed scope, and token exchange
  returning `401 access_denied` for a denied resource;
- device flow: approve, deny, or leave pending per device code; emits
  `slow_down` on demand;
- records every request with decoded form parameters.

`ManualClock` implements `Clock<Duration>`; `sleep` suspends until the
test advances time. `waitForSleeper()` and `advanceToNextSleeper()` wait for a
sleeper in real time and stop the process with a clear message after 10 s
instead of hanging; `waitForSleeper(timeout:)` returns `false` instead. `FixedWallClock` returns a settable `Date`.

## 15. Quality gates

- `make check` (format lint, determinism grep, build with warnings as
  errors, all tests) passes on macOS; the core and testing modules build
  and test on Linux.
- `make docs` (DocC archives of all three libraries) has no warning, so
  every symbol link resolves. `make integration` passes against the local
  server.
- No `Date()`, `Date.now`, `Task.sleep`, `URLSession.shared`, `UUID()` or
  random APIs (`.random(`, `arc4random`, `SystemRandomNumberGenerator`) in
  core outside the default `SystemWallClock`, `SystemRandomSource` and
  `URLSessionTransport` implementations: `scripts/check-determinism.sh`,
  run by `make lint` and therefore by CI.
- Redaction canary test (`Tests/ConformanceTests/RedactionCanaryTests.swift`):
  a run of every flow with canary secrets, including error paths where the
  server repeats the secrets it was sent, finds no canary in any error
  description, event, `String(describing:)`, `String(reflecting:)` or `dump`
  of public values.
- DocC comments on every public symbol; the article samples are compiled in
  `Tests/ConformanceTests/DocumentationSnippets.swift`.
