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
