# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

First development cycle; nothing is released yet.

### Added

#### Core (`PassportKit`)

- Foundations: `Secret`, `ScopeSet`, `AdditionalParameters`, `JSONValue`, `GrantType`, `TokenTypeIdentifier`,
  `TokenTypeHint`, the `WallClock` and `RandomSource` seams, HTTP types with `URLSessionTransport`
  (`init(configuration:requestTimeout:resourceTimeout:)`, 30 s and 60 s defaults), `PassportError`,
  `TokenResponse`, and the endpoint and client authentication configuration types.
- `OAuthClient` with refresh, client credentials, token exchange, extension grants and revocation, plus
  `TokenExchangeRequest`, `PassportObserver`, `PassportEvent` and `EndpointKind`. `configuration` and `wallClock`
  are public, and a description shows the client ID and token endpoint only.
- `PassportEvent.transportFailure(endpoint:grantType:duration:)`, so every `.request` event has a terminating event.
- Device authorization grant (RFC 8628): `beginDeviceAuthorization` and `completeDeviceAuthorization` with interval,
  `slow_down`, back-off, expiry and cancellation handling, and the `DeviceAuthorization` value.
- Authorization code grant with PKCE `S256` (RFC 7636): `beginAuthorization`, `completeAuthorization` and
  `authorize(_:using:)`, with `AuthorizationRequest` (`lifetime`, default 10 minutes), `PendingAuthorization` and
  `AuthorizationUserAgent`, `state` and redirect checks, and `iss` validation (RFC 9207) with
  `ClientConfiguration.requiresIssuerInAuthorizationResponse`.
- Authorization server metadata (RFC 8414): `Discovery.fetchMetadata(issuer:style:validation:transport:observer:clock:)`,
  `AuthorizationServerMetadata` with preserved unknown members, `IssuerValidation`, `Endpoints.init(metadata:)` and
  `ClientConfiguration.init(metadata:authentication:)`, which turns on `iss` checking when the server advertises it.
- `AuthenticationChallenge.parse` for `WWW-Authenticate` values (RFC 9110 §11.6.1, RFC 6750 §3).
- `TokenManager`, the session actor: `load`, `signIn`, `accessToken(for:)`, `invalidate`, `exchangeRefreshToken` and
  `signOut(revoke:)`, with a FIFO lane for every operation that sends the refresh token, coalescing per
  `TokenTarget`, persist-before-publish of rotated refresh tokens, generation checks, expiry rules and a multicast
  `events` stream. Adds `TokenTarget`, `AccessToken`, `TokenAcceptancePolicy` (`AcceptAnyToken`, `RequireAnyScope`),
  `SessionEvent`, `SignOutReason` and `SignOutResult`; `init(acceptancePolicyTimeLimit:rejectedTokenCacheDuration:)`,
  `SignOutReason.expiredWithoutRefreshToken` and `SignOutResult.Revocation.cancelled`.
- Credential storage: `Credential`, `CredentialAccount`, `CredentialStore`, `InMemoryCredentialStore` and the
  versioned JSON `CredentialCoding`.
- `RequestAuthorizer` and `RetryDecision`: sign `URLRequest` and `HTTPRequest` with a bearer token (https or
  loopback only), decide what a 401 or 403 means (RFC 6750 §3.1), `send(_:for:)` and
  `data(for:target:session:)` with at most one retry.
- `Retry-After` is also read as an HTTP-date.

#### Apple platforms (`PassportKitApple`)

- `KeychainCredentialStore`: non-synchronizable generic password items updated in place, an accessibility class
  option, optional data protection keychain on macOS and a `decodeLegacy` migration hook.
- `WebAuthenticationSessionUserAgent` (`ASWebAuthenticationSession`), `LoopbackRedirectListener` and
  `LoopbackUserAgent` (RFC 8252).

#### Testing (`PassportKitTesting`)

- `FakeAuthorizationServer`, `ManualClock` (`waitForSleeper(timeout:)`), `ManualWallClock`, `SequenceRandomSource`
  and `RecordingTransport`. The server rotates refresh tokens on token exchange with a refresh-token subject, can
  issue a refresh token (`requested_token_type`), and delays responses with `Controls.responseDelay`.

#### Documentation and tooling

- DocC catalogs for all three libraries, with articles on getting started, sessions and token targets, resource
  access and scopes, error handling, native app redirects and testing; `make docs` builds them and fails on any
  warning, and CI runs it. `.spi.yml` for the Swift Package Index.
- `passportkit-example`, a command-line client for the device and loopback code flows, and an integration test
  suite against a local `oidc-provider` server (`make integration`).
- `scripts/check-determinism.sh`, run by `make lint`, keeps system clocks, random APIs and `URLSession.shared` out
  of the core.
- A redaction canary test that searches every error, event and description for the secrets of every flow.

### Changed

- A token exchange response without `issued_token_type` is rejected (RFC 8693 §2.2.1).
- The `resource` indicators of an authorization request are repeated on its token request (RFC 8707 §2.2).
- `additionalParameters` may not use `client_id` or `client_secret`.
- A device authorization response needs an `https` (or loopback `http`) verification URI and an `interval` of at
  most one hour.
- A redirect callback with userinfo is rejected, and a query on the registered redirect URI must be present in the
  callback.
- Server error codes that are not well-formed RFC 6749 §5.2 values become `invalidResponse`; `error_uri` keeps only
  `http(s)` URLs.
- `URLSessionTransport` drops all non-standard headers on cross-origin redirects and returns a complete response
  even when the caller cancelled.
- `ManualClock.waitForSleeper()` stops with a clear message after 10 s instead of spinning forever.
- `TokenManager` hardening (ADR 0007): store changes are applied in order, a sign-out revokes the newest refresh
  token even when a request rotated it meanwhile, each session has its own refresh lane, `signIn` no longer lets a
  concurrent `accessToken()` spend the grant's first refresh token, callers of a replaced session get a token of the
  new one, the acceptance policy has a time limit, a rejected token is remembered for 30 s instead of being
  requested again, event streams buffer 64 events, a grant without a refresh token ends its session when its access
  token expires, and `TokenTarget` ignores the order and repetition of resources and audiences.

### Changed: public API review before the first release

- Evolvable types: `ClientAuthentication`, `TokenTarget.Derivation` (was the enum `TokenTarget.Method`),
  `EndpointKind` and `TokenTypeHint` are open structs with static members, so new cases are not source breaking.
  `ClientAuthentication.none(clientID:)` is now `.publicClient(clientID:)`. `TokenTarget` is created with
  `.refreshGrant(resources:scope:)` or `.exchange(resources:audiences:scope:)`; its `method` property is
  `derivation`, with `.refreshGrant` and `.tokenExchange`. `PassportError.Recovery.none` is `.noAction`.
  `Recovery`, `RetryDecision`, `SessionEvent`, `SignOutReason` and `SignOutResult.Revocation` are documented as
  not frozen.
- Less accidental surface: `ClientConfiguration.validate()`, `Endpoints.validate()`,
  `PassportError.maximumDescriptionLength`, `URLSessionTransport.maximumBodySize`, `CredentialCoding.currentVersion`
  and `TokenResponse.isBearer` are internal, `AccessToken.init` is package-only and `AccessToken.generation` is
  read-only. `DeviceAuthorization` has read-only properties and a public initializer for previews and UI tests.

- `RequestAuthorizer` takes its transport at creation (`init(manager:transport:)`, `URLSessionTransport()` by
  default), so `send(_:for:using:)` is `send(_:for:)`; `authorize(_:for:)` is `sign(_:for:)`, which no longer
  clashes with `OAuthClient.authorize(_:using:)`.

- `TokenManager.signIn(with:requestedScope:)` defaults `requestedScope` to `nil`, and the documentation of
  `TokenManager.init` warns that the default `AcceptAnyToken` accepts narrowed tokens.
  `TokenAcceptancePolicy.evaluate(_:)` takes a `TokenAcceptanceContext` (token, response, target) instead of two
  arguments. `RequireAnyScope(_:forTargets:)` takes a `TargetSelector` (`.withResources`, `.all`,
  `.matching { }`) instead of a `when:` closure. New: `ClosureTokenAcceptancePolicy` and `.custom { }`.

- `AuthorizationRequest.prompt` is `[AuthorizationRequest.Prompt]` instead of a string: an open struct with
  `.noInteraction` (the value `none`), `.login`, `.consent` and `.selectAccount`, sent as one space-delimited
  parameter, so several values can be combined.

- Conformances: `Hashable` for `HTTPRequest`, `HTTPResponse`, `TokenResponse`, `TokenExchangeRequest`,
  `AuthorizationRequest` and `SessionEvent`; `Codable` for `PassportError.Code`; `PassportError` is a
  `LocalizedError` whose `errorDescription` is its redacted `description`. The sanitized server text that was
  `PassportError.errorDescription` is now `PassportError.detail` (and the `detail:` initializer parameter),
  because the name belongs to `LocalizedError`.

- Naming: `UserAgent` is `AuthorizationUserAgent`; `OAuthClient.refresh(_:scope:resources:additionalParameters:)`
  takes the refresh token without a label; `startDeviceAuthorization` is `beginDeviceAuthorization`, pairing with
  `completeDeviceAuthorization` like `beginAuthorization` and `completeAuthorization`;
  `TokenManager.exchangeRefreshToken(audiences:)` takes an array like `TokenExchangeRequest.audiences`;
  `HTTPHeaders.add(name:value:)` is `append(_:_:)`, like `AdditionalParameters.append(_:_:)`.

- `PassportKitTesting`: every lifetime and interval is a `Duration` (`ClientRegistration.accessTokenLifetime`,
  `refreshTokenLifetime`, `RotationLeeway.window` (was `seconds`), `Controls.deviceCodeLifetime`,
  `Controls.deviceInterval`); `FixedWallClock` is `ManualWallClock`, matching `ManualClock`;
  `FakeAuthorizationServer.makeClient(clientID:wallClock:clock:)` and `userAgent(subject:decision:)` replace the
  hand-written client and user agent of every test; `revoke(token:)`, `expire(token:)` and `details(of:)` take a
  `Secret`, with `String` overloads.

### Security

- `RequestAuthorizer` sends only `Bearer` tokens (compared case-insensitively). Another token type fails with
  `invalidConfiguration` before anything is sent, so a sender-constrained token is never sent as a bearer
  credential.
- Credentials a server echoes in `error_description` are redacted, however short: refresh, subject, actor and device
  codes, authorization codes, PKCE verifiers, client secrets, revoked tokens, and the bearer token in a
  `WWW-Authenticate` description. Previously only runs of 24 or more characters were.
- Dumping an `OAuthClient` no longer reaches the injected transport or observer.
- `HTTPHeaders` no longer prints header values (names only) in descriptions, `debugDescription` and reflection.
- Error descriptions lose control, line-separator and invisible format characters.
- Hostile `interval`, `expires_in` and `slow_down` values can no longer trap device polling.
- `Secret` documents that `Codable` encodes plaintext.

### Fixed

- `FakeAuthorizationServer.authorizeInteractively` decodes the authorization request query as form data, so a `+` in
  `scope` is a space.
