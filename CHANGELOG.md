# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `TokenManager.signIn(refreshToken:grantedScope:idToken:)` starts a session from an existing refresh token, for
  example the one `exchangeRefreshToken(audiences:)` issued for another client. It replaces the session, saves the
  credential and emits `.signedIn` like `signIn(with:requestedScope:)`, but caches no access token: the first
  `accessToken(for:)` refreshes.

### Changed

- **Breaking (`PassportKitTesting`):** `ManualClock.waitForSleeper()` and `ManualClock.advanceToNextSleeper()` are
  now `throws`; call them with `try await`. When no task sleeps within 60 seconds of real time (it was 10 seconds)
  they throw the new `ManualClock.WaitTimeout` instead of stopping the whole test process, so a slow wake-up on a
  loaded machine fails only the waiting test. The wait is resumed by the sleeper that arrives instead of
  polling. `waitForSleeper(timeout:)` is unchanged.

- `KeychainCredentialStore` sets `kSecAttrSynchronizable` to `false` explicitly when it adds, fetches and deletes
  an item, instead of relying on the default. Items written before are found as before.

### Fixed

- The documentation of `KeychainCredentialStore`, `KeychainCredentialStore.Accessibility` and the security model
  said accessibility classes and access groups protect the item. On macOS the store uses the file-based login
  keychain, which enforces neither; they apply on iOS. The note that a failed legacy write-back is retried by the
  next load is corrected: SwiftKeychain deletes before it adds, so a failed write-back can leave nothing stored.

- `KeychainCredentialStore.delete` matches the item by service, account and access group only. It no longer
  carries the accessibility class, so an item stored with another class is removed on sign-out, and it no
  longer matches items of other access groups.

## [0.1.0] - 2026-10-12

First release.

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
- `RequestAuthorizer(manager:transport:allowedOrigins:)` limits the origins a token may be sent to.

- Logging through swift-log: `logger: Logger = Logger(label: "PassportKit")` on `OAuthClient.init` (with a public
  `logger` property), `Discovery.fetchMetadata`, `KeychainCredentialStore.init`, `LoopbackRedirectListener.start` and
  `WebAuthenticationSessionUserAgent.init`, and `logger: Logger? = nil` on `TokenManager.init` (defaults to the
  client's). `PassportObserver` is unchanged. See `docs/spec.md` for the level policy.

#### Apple platforms (now part of `PassportKit`)

- `KeychainCredentialStore`: non-synchronizable generic password items updated in place, an accessibility class
  option and a `decodeLegacy` migration hook.
- `WebAuthenticationSessionUserAgent` (`ASWebAuthenticationSession`), `LoopbackRedirectListener` and
  `LoopbackUserAgent` (RFC 8252). `waitForCallback(timeout:accept:)` takes a predicate that decides which
  authorization-response-shaped request ends the wait; `LoopbackUserAgent` passes one that matches `state`.

#### Testing (`PassportKitTesting`)

- `FakeAuthorizationServer`, `ManualClock` (`waitForSleeper(timeout:)`), `ManualWallClock`, `SequenceRandomSource`
  and `RecordingTransport`. The server rotates refresh tokens on token exchange with a refresh-token subject, can
  issue a refresh token (`requested_token_type`), delays responses with `Controls.responseDelay`, and can leave
  `scope` out of token responses with `Controls.omitsScope`.

#### Documentation and tooling

- DocC catalogs for the libraries, with articles on getting started, sessions and token targets, resource
  access and scopes, error handling, native app redirects and testing; `make docs` builds them and fails on any
  warning, and CI runs it. `.spi.yml` for the Swift Package Index.
- `passportkit-example`, a command-line client for the device and loopback code flows, and an integration test
  suite against a local `oidc-provider` server (`make integration`).
- `scripts/check-determinism.sh`, run by `make lint`, keeps system clocks, random APIs and `URLSession.shared` out
  of the core.
- A redaction canary test that searches every error, event and description for the secrets of every flow.

### Changed

- **Breaking:** HTTP currency types come from [swift-http-types](https://github.com/apple/swift-http-types)
  (`from: "1.5.0"`, ADR 0010). `HTTPMethod`, `HTTPHeaders`, `HTTPRequest` and `HTTPResponse` are removed; use
  `HTTPRequest.Method`, `HTTPFields` and `HTTPField.Name`, `HTTPTypes.HTTPRequest` and `HTTPTypes.HTTPResponse`
  (`import HTTPTypes`). `HTTPTransport.send(_:)` is `send(_:body:)` and returns `(HTTPResponse, Data)`; requests carry
  an absolute URL (`HTTPRequest(method:url:headerFields:)`). `ClientConfiguration.additionalHeaders` and
  `RequestAuthorizer.evaluate(statusCode:headers:token:attempt:)` take `HTTPFields`; `RequestAuthorizer.send(_:for:)`
  is `send(_:body:for:)` and returns `(HTTPResponse, Data)`. In `PassportKitTesting`, `RecordedRequest.headers` is
  `headerFields` and `url` is optional, `RecordedRequest` has a `body`, `RecordingTransport.Step.respond` takes a
  response and its body, and `FakeAuthorizationServer.ResponseOverride` has a `body`. `URLSessionTransport` converts
  with `HTTPTypesFoundation`; its behaviour is unchanged. `Hashable` for `HTTPRequest` and `HTTPResponse` is gone.
- Dependencies: the core depends on swift-log (`Logging`,
  `from: 1.6.0`); SwiftKeychain (`.upToNextMinor(from: "2.1.0")`) is a dependency too. The hand-written
  SHA-256 and the "no third-party runtime dependencies" policy are gone (ADR 0009, which supersedes parts of
  ADR 0002).
- `KeychainCredentialStore` is built on SwiftKeychain and no longer takes `useDataProtectionKeychain` (SwiftKeychain
  cannot target the data protection keychain). Records written directly as JSON are still read. Known issue:
  SwiftKeychain replaces an existing item by delete-then-add, which can lose the credential if the add fails; see
  `docs/security-model.md`.
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

### Changed: Apple platforms only (breaking)

Linux support is dropped ([ADR 0011](docs/decisions/0011-apple-platforms-only.md)). The minimum platforms are
unchanged: macOS 14, iOS 17, tvOS 17, watchOS 10 and visionOS 1.

- `PassportKitApple` is merged into `PassportKit`: remove the `PassportKitApple` product from your target and
  `import PassportKitApple`; `KeychainCredentialStore`, `WebAuthenticationSessionUserAgent`,
  `LoopbackRedirectListener` and `LoopbackUserAgent` come from `import PassportKit`. SwiftKeychain is now a
  dependency of `PassportKit`.
- `WebAuthenticationSessionUserAgent` is unavailable on tvOS and watchOS (as before, now declared by `#if os`), and
  `LoopbackRedirectListener` and `LoopbackUserAgent` are only available on macOS, iOS and visionOS. The default
  `openURL` of `LoopbackUserAgent` no longer has an unsupported-platform fallback.
- SHA-256 uses CryptoKit; the swift-crypto dependency is removed from `PassportKit` and `PassportKitTesting`.
- Shared state is guarded by `OSAllocatedUnfairLock` instead of `NSLock` with `@unchecked Sendable`.
  `ManualClock.Instant` is `Sendable`.
- The Linux CI job and the `canImport(FoundationNetworking)` code paths are gone.

### Removed

- The `PassportKitApple` product and target, the `PassportKitApple` DocC catalog, and Linux support.

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

- Conformances: `Hashable` for `TokenResponse`, `TokenExchangeRequest`,
  `AuthorizationRequest` and `SessionEvent`; `Codable` for `PassportError.Code`; `PassportError` is a
  `LocalizedError` whose `errorDescription` is its redacted `description`. The sanitized server text that was
  `PassportError.errorDescription` is now `PassportError.detail` (and the `detail:` initializer parameter),
  because the name belongs to `LocalizedError`.

- Naming: `UserAgent` is `AuthorizationUserAgent`; `OAuthClient.refresh(_:scope:resources:additionalParameters:)`
  takes the refresh token without a label; `startDeviceAuthorization` is `beginDeviceAuthorization`, pairing with
  `completeDeviceAuthorization` like `beginAuthorization` and `completeAuthorization`;
  `TokenManager.exchangeRefreshToken(audiences:)` takes an array like `TokenExchangeRequest.audiences`.

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
- `ClientConfiguration`, `RecordedRequest`, `RecordingTransport.Step` and `FakeAuthorizationServer.ResponseOverride`
  print header names only, never values, in descriptions, `debugDescription` and reflection. swift-http-types prints
  header values and the URL query in its own types, so a signed `HTTPRequest` and the responses the library returns
  are the caller's values: do not log them. `Authorization` is marked never indexed (HPACK, RFC 7541 §7.1.3).
- Error descriptions lose control, line-separator and invisible format characters.
- Hostile `interval`, `expires_in` and `slow_down` values can no longer trap device polling.
- `Secret` documents that `Codable` encodes plaintext.
- The loopback listener ignores requests that are not authorization responses (no `state`, or neither `code` nor
  `error`) and requests that `Sec-Fetch-Mode` or `Sec-Fetch-Dest` mark as background fetches, so a web page cannot use
  up the one-shot redirect. It serves at most 8 connections, closes each after 5 seconds, closes them on `cancel()`
  and on delivery, and stops when it is released.
- `RequestAuthorizer` refuses a token that is not a valid `b64token` (RFC 6750 §2.1) instead of writing it into a
  header, and `data(for:target:session:)` applies the library's redirect policy (no HTTPS to HTTP, credential
  headers dropped across origins) whatever the session's own delegate does.
- A device `user_code` with control or invisible format characters, or over 64 characters, is an invalid response;
  the example executable prints server text through a sanitizer.
- The token cache drops expired tokens and rejections when it grows and keeps at most 256 of each.
- The integration server listens on `127.0.0.1` only.

### Fixed

- A refresh without `scope` against a server that also omits `scope` from the response now yields a token with the
  originally granted scope (RFC 6749 §5.1, §6), and a refresh that renews the whole grant records the scope the
  server returned in the credential. Before, the token's scope was unknown and `RequireAnyScope` rejected it.
- A `resource` indicator may be any absolute URI, such as `urn:example:api`, not only a URL with a host (RFC 8707 §2).
- A 401 that carries challenges for other schemes only (`Basic`, `DPoP`) is delivered instead of refreshing the token.
- `FakeAuthorizationServer.authorizeInteractively` decodes the authorization request query as form data, so a `+` in
  `scope` is a space.

[Unreleased]: https://github.com/slidoapp/PassportKit/compare/0.1.0...HEAD
[0.1.0]: https://github.com/slidoapp/PassportKit/releases/tag/0.1.0
