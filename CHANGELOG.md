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
