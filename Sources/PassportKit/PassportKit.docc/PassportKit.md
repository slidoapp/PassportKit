# ``PassportKit``

A vendor-neutral OAuth 2.0 client for Swift 6.

## Overview

PassportKit talks to any standards-compliant authorization server. It
implements the grants and companion specifications an app needs to sign a
person in and call protected resources: authorization code with PKCE,
device authorization, refresh tokens with rotation, token exchange, resource
indicators, authorization server metadata, token revocation, and bearer
token usage.

Two layers fit together:

- ``OAuthClient`` is stateless. Each method sends one protocol request and
  returns the parsed result or throws a ``PassportError``.
- ``TokenManager`` is the session. It owns the refresh token, keeps it safe
  across rotation and concurrency, caches access tokens per
  ``TokenTarget`` and applies your acceptance policy before a token is used.
  ``RequestAuthorizer`` signs requests with its tokens.

Time, randomness and the HTTP transport are injected, so every flow can be
tested without a network or sleeping (see <doc:Testing>). Secrets never
appear in descriptions, errors or events.

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:SessionsAndTokenTargets>
- <doc:ResourceAccessAndScopes>
- <doc:ErrorHandling>
- <doc:NativeAppRedirects>
- <doc:Testing>

### Configuring a client

- ``ClientConfiguration``
- ``Endpoints``
- ``ClientAuthentication``
- ``Discovery``
- ``AuthorizationServerMetadata``
- ``IssuerValidation``
- ``OAuthClient``

### Signing in

- ``AuthorizationRequest``
- ``PendingAuthorization``
- ``AuthorizationUserAgent``
- ``DeviceAuthorization``

### Token requests and responses

- ``TokenResponse``
- ``TokenExchangeRequest``
- ``GrantType``
- ``TokenTypeIdentifier``
- ``TokenTypeHint``
- ``AdditionalParameters``
- ``ScopeSet``
- ``JSONValue``

### Sessions

- ``TokenManager``
- ``TokenTarget``
- ``AccessToken``
- ``Credential``
- ``SignOutResult``
- ``SignOutReason``
- ``SessionEvent``

### Accepting tokens

- ``TokenAcceptancePolicy``
- ``TokenAcceptance``
- ``AcceptAnyToken``
- ``RequireAnyScope``

### Credential storage

- ``CredentialStore``
- ``CredentialAccount``
- ``InMemoryCredentialStore``
- ``CredentialCoding``

### Calling protected resources

- ``RequestAuthorizer``
- ``RetryDecision``
- ``AuthenticationChallenge``

### Errors

- ``PassportError``

### Observability

- ``PassportObserver``
- ``PassportEvent``
- ``EndpointKind``

### HTTP

- ``HTTPTransport``
- ``URLSessionTransport``
- ``HTTPRequest``
- ``HTTPResponse``
- ``HTTPHeaders``
- ``HTTPMethod``

### Time and randomness

- ``WallClock``
- ``RandomSource``
- ``SystemWallClock``
- ``SystemRandomSource``

### Secrets

- ``Secret``
