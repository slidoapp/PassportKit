# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Foundations of the core module: `Secret`, `ScopeSet`, `AdditionalParameters`,
  `JSONValue`, `GrantType`, `TokenTypeIdentifier`, `TokenTypeHint`, the
  `WallClock` and `RandomSource` seams, HTTP types with `URLSessionTransport`,
  `PassportError`, `TokenResponse`, and the endpoint and client
  authentication configuration types.
- `OAuthClient` with refresh, client credentials, token exchange, extension
  grants and revocation, plus `TokenExchangeRequest`, `PassportObserver`,
  `PassportEvent` and `EndpointKind`.
- Device authorization grant: `OAuthClient.startDeviceAuthorization` and
  `completeDeviceAuthorization` with interval, `slow_down`, backoff, expiry
  and cancellation handling, and the `DeviceAuthorization` value.
- `PassportEvent.transportFailure(endpoint:grantType:duration:)`, emitted when
  a request ends without an HTTP response, so every `.request` event has a
  terminating event.
- Authorization code grant with PKCE (S256): `OAuthClient.beginAuthorization`,
  `completeAuthorization` and `authorize(_:using:)`, the `AuthorizationRequest`,
  `PendingAuthorization` and `UserAgent` types, `state` and redirect checks,
  and `iss` validation (RFC 9207) with the new
  `ClientConfiguration.requiresIssuerInAuthorizationResponse` option.
- Authorization server metadata discovery (RFC 8414): `Discovery.fetchMetadata`,
  `AuthorizationServerMetadata` with preserved unknown members,
  `IssuerValidation`, and `Endpoints.init(metadata:)`.
- `AuthenticationChallenge.parse` for `WWW-Authenticate` values (RFC 9110
  §11.6.1, RFC 6750 §3).
- `TokenManager`, the session actor: `load`, `signIn`, `accessToken(for:)`,
  `invalidate`, `exchangeRefreshToken` and `signOut(revoke:)`, with a FIFO
  lane for every operation that sends the refresh token, coalescing per
  `TokenTarget`, persist-before-publish of rotated refresh tokens,
  generation checks, expiry rules and a multicast `events` stream. Adds
  `TokenTarget`, `AccessToken`, `TokenAcceptancePolicy` (`AcceptAnyToken`,
  `RequireAnyScope`), `SessionEvent`, `SignOutReason` and `SignOutResult`.
- Credential storage: `Credential`, `CredentialAccount`, `CredentialStore`,
  `InMemoryCredentialStore` and the versioned JSON `CredentialCoding`.
- `OAuthClient.configuration` and `OAuthClient.wallClock` are public.
- `PassportKitTesting`: `FakeAuthorizationServer` rotates refresh tokens on
  token exchange with a refresh-token subject, can issue a refresh token
  (`requested_token_type`), and delays responses with `Controls.responseDelay`.

- `ClientConfiguration.init(metadata:authentication:)` takes the endpoints and
  issuer from discovered metadata and turns on `iss` checking when the server
  advertises it (RFC 9207 §3).
- `AuthorizationRequest.lifetime` (default 10 minutes);
  `URLSessionTransport.init(configuration:requestTimeout:resourceTimeout:)`
  with 30 s and 60 s defaults; `Discovery.fetchMetadata(observer:clock:)`;
  `ManualClock.waitForSleeper(timeout:)`.
- `Retry-After` is also read as an HTTP-date.

### Changed

- A token exchange response without `issued_token_type` is rejected
  (RFC 8693 §2.2.1).
- The `resource` indicators of an authorization request are repeated on its
  token request (RFC 8707 §2.2).
- `additionalParameters` may not use `client_id` or `client_secret`.
- A device authorization response needs an `https` (or loopback `http`)
  verification URI and an `interval` of at most one hour.
- A redirect callback with userinfo is rejected, and a query on the registered
  redirect URI must be present in the callback.
- Server error codes that are not well-formed RFC 6749 §5.2 values become
  `invalidResponse`; `error_uri` keeps only `http(s)` URLs; descriptions lose
  invisible format characters.
- `URLSessionTransport` drops all non-standard headers on cross-origin
  redirects and returns a complete response even when the caller cancelled.
- `ManualClock.waitForSleeper()` stops with a clear message after 10 s
  instead of spinning forever.

### Security

- `HTTPHeaders` no longer prints header values (names only) in descriptions,
  `debugDescription` and reflection.
- Hostile `interval`, `expires_in` and `slow_down` values can no longer trap
  device polling.
- `Secret` documents that `Codable` encodes plaintext.

### Fixed

- `FakeAuthorizationServer.authorizeInteractively` decodes the authorization
  request query as form data, so a `+` in `scope` is a space.

