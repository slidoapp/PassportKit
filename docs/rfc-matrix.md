# RFC Traceability Matrix

Every protocol behaviour in PassportKit maps to a row here. Add or update
rows in the same change as the code and its test.

Status values: `planned`, `partial`, `done`, `not planned` (give the
reason in Notes).

## Scope

| RFC | Title | Status | Notes |
|---|---|---|---|
| 6749 | OAuth 2.0 Authorization Framework | partial | Authorization code, refresh, client credentials. No implicit or password grants. |
| 6750 | Bearer Token Usage | partial | Authorization header only; `WWW-Authenticate` challenge parsing; `RequestAuthorizer`. No form-body or query-parameter tokens. |
| 7636 | PKCE | done | S256 always; `plain` not supported. |
| 8252 | OAuth 2.0 for Native Apps | partial | System browser, loopback and claimed HTTPS redirects. |
| 8628 | Device Authorization Grant | planned | |
| 8693 | Token Exchange | partial | Access-token and refresh-token subjects. |
| 8707 | Resource Indicators | done | |
| 8414 | Authorization Server Metadata | done | Configurable issuer validation. |
| 7009 | Token Revocation | planned | |
| 9207 | Authorization Server Issuer Identification | done | |
| 9700 | OAuth 2.0 Security Best Current Practice | planned | Applied across all flows. |
| 7662 | Token Introspection | not planned | Resource-server concern. |
| 9449 | DPoP | not planned | Candidate for a later version. |
| 9126 | Pushed Authorization Requests | not planned | Candidate for a later version. |

## Requirements

| ID | RFC § | Level | Requirement | Status | Code | Test |
|---|---|---|---|---|---|---|
| FORM-1 | 6749 App. B | MUST | Form bodies are UTF-8; all but unreserved characters percent-encoded, space as `+` | done | `Sources/PassportKit/HTTP/FormEncoding.swift` | `FormEncodingTests` |
| AUTH-1 | 6749 §2.3.1 | MUST | Basic client credentials: client id and secret form-encoded before base64 | done | `Sources/PassportKit/Configuration/ClientAuthentication.swift` | `ClientAuthenticationTests` |
| AUTH-3 | 6749 §2.3 | MUST | At most one client authentication method per request: `client_id` and `client_secret` are reserved against additional parameters in every mode | done | `Sources/PassportKit/Client/FormRequest.swift`, `Core/AdditionalParameters.swift` | `ClientAuthenticationTests` |
| AUTH-2 | 6749 §2.3.1, §3.2.1 | MAY | `client_secret` in the body; public clients send `client_id` | done | `Sources/PassportKit/Configuration/ClientAuthentication.swift` | `ClientAuthenticationTests` |
| TLS-1 | 6749 §3.1, §3.2; 8252 §8.3 | MUST | Endpoints use TLS; plain `http` only on loopback hosts | done | `Sources/PassportKit/Configuration/Endpoints.swift` | `EndpointsTests` |
| TOK-1 | 6749 §5.1 | MUST | Success response needs `access_token` and `token_type`; `token_type` compared case-insensitively | done | `Sources/PassportKit/Tokens/TokenResponse+Parsing.swift` | `TokenResponseTests` |
| TOK-2 | 6749 §5.1 | MUST | Unknown response members are ignored by the protocol and preserved for the app | done | `Sources/PassportKit/Tokens/TokenResponse+Parsing.swift` | `TokenResponseTests` |
| TOK-3 | 6749 §3.3, §5.1 | MUST | Omitted `scope` means the requested scope was granted; response `scope` is exposed as returned | done | `Sources/PassportKit/Tokens/TokenResponse.swift` | `TokenResponseTests` |
| TOK-4 | 6749 §5.1 | SHOULD | `expires_in` read from a number or numeric string; absence tolerated | done | `Sources/PassportKit/Tokens/TokenResponse+Parsing.swift` | `TokenResponseTests` |
| ERR-1 | 6749 §5.2 | MUST | Error responses classified by the JSON `error` code, not by HTTP status | done | `Sources/PassportKit/Errors/PassportError+Classification.swift` | `ErrorClassificationTests` |
| ERR-2 | 6749 §5.2 | MUST | `error_description` and `error_uri` preserved; description sanitized (controls, line separators, invisible format characters, token-like runs) and truncated; `error_uri` only `http(s)` | done | `Sources/PassportKit/Errors/PassportError.swift`, `PassportError+Classification.swift` | `PassportErrorTests`, `ErrorClassificationTests` |
| ERR-5 | 6749 §5.2, §4.1.2.1 | MUST | A server `error` code outside `%x20-21 / %x23-5B / %x5D-7E` or longer than 64 characters is not trusted: `invalidResponse`, no raw text kept | done | `Sources/PassportKit/Errors/PassportError+Code.swift`, `PassportError+Classification.swift`, `Client/OAuthClient+AuthorizationCode.swift` | `ErrorClassificationTests`, `AuthorizationCompletionTests` |
| ERR-3 | 6749 §6; 8693 §2.2.2 | MUST | `invalid_grant` on a refresh-token-consuming request ends the session; elsewhere it does not | done | `Sources/PassportKit/Errors/PassportError+Classification.swift` | `ErrorClassificationTests` |
| ERR-4 | 9110 §10.2.3 | SHOULD | `Retry-After` delta-seconds and HTTP-date (IMF-fixdate and the two obsolete forms, relative to the injected wall clock) honoured on 429 and 5xx | done | `Sources/PassportKit/Errors/PassportError+Classification.swift` | `ErrorClassificationTests` |
| PKCE-1 | 7636 §4.1 | MUST | Verifier from 32 random octets, base64url without padding (43 characters) | done | `Sources/PassportKit/PKCE/PKCE.swift` | `PKCETests` |
| PKCE-2 | 7636 §4.2, App. B | MUST | `S256` challenge is base64url(SHA-256(ASCII(verifier))); Appendix B vector passes | done | `Sources/PassportKit/PKCE/PKCE.swift`, `PKCE/PureSwiftSHA256.swift` | `PKCETests`, `SHA256Tests` |
| TRN-1 | 6749 §3.2 | MUST | Token endpoint requests do not follow redirects (`POST`) | done | `Sources/PassportKit/HTTP/URLSessionTransportDelegate.swift` | `URLSessionTransportTests` |
| TRN-2 | 6749 §10.3 | SHOULD | Redirects never leave HTTPS for HTTP; a redirect to another origin drops every non-standard request header | done | `Sources/PassportKit/HTTP/URLSessionTransportDelegate.swift` | `URLSessionTransportTests` |
| TRN-3 | 6749 §10 | SHOULD | Requests time out (30 s idle, 60 s total by default); a complete response survives a late cancellation so a rotated refresh token is not lost | done | `Sources/PassportKit/HTTP/URLSessionTransport.swift` | `URLSessionTransportTests` |
| GRANT-1 | 6749 §6 | MUST | Refresh grant sends `grant_type`, `refresh_token` and optional `scope`; `invalid_grant` ends the session | done | `Sources/PassportKit/Client/OAuthClient+TokenGrants.swift` | `OAuthClientTests` |
| GRANT-2 | 6749 §4.4 | MUST | Client credentials grant sends `grant_type` and optional `scope` with client authentication | done | `Sources/PassportKit/Client/OAuthClient+TokenGrants.swift` | `OAuthClientTests` |
| GRANT-3 | 6749 §4.5 | MAY | Extension grants through `requestToken(grantType:parameters:)` with full error parsing | done | `Sources/PassportKit/Client/OAuthClient+TokenGrants.swift` | `OAuthClientTests` |
| XCH-1 | 8693 §2.1 | MUST | Exchange sends `subject_token(_type)`, optional actor token and types, `requested_token_type`, repeated `audience`, `resource`, `scope`; actor token needs its type | done | `Sources/PassportKit/Client/OAuthClient+TokenGrants.swift` | `OAuthClientTests` |
| XCH-4 | 8693 §2.2.1 | MUST | An exchange response without `issued_token_type` is invalid | done | `Sources/PassportKit/Tokens/TokenResponse+Parsing.swift` | `OAuthClientTests` |
| XCH-2 | 8693 §2.2.1 | MUST | `token_type` may be `N_A` or absent when `issued_token_type` is not an access token | done | `Sources/PassportKit/Tokens/TokenResponse+Parsing.swift` | `OAuthClientTests` |
| XCH-3 | 8693 §2.2.2; 6749 §5.2 | MUST | Exchange errors classified by body; `invalid_grant` with a refresh-token subject ends the session | done | `Sources/PassportKit/Client/OAuthClient+TokenGrants.swift` | `OAuthClientTests` |
| RES-1 | 8707 §2 | MUST | `resource` is an absolute URI without fragment, sent as a repeated parameter | done | `Sources/PassportKit/Client/ParameterList.swift` | `OAuthClientTests` |
| RES-2 | 8707 §2.2 | SHOULD | The resources of an authorization request are repeated on its token request | done | `Sources/PassportKit/Client/OAuthClient+AuthorizationCode.swift` | `AuthorizationCompletionTests` |
| REV-1 | 7009 §2.1 | MUST | Revocation request sends `token` and optional `token_type_hint` with client authentication; missing endpoint is a configuration error | done | `Sources/PassportKit/Client/OAuthClient+Revocation.swift` | `OAuthClientTests` |
| REV-2 | 7009 §2.2, §2.2.1 | MUST | A 200 response is success whatever its body; 503 with `Retry-After` is retryable; error JSON is parsed | done | `Sources/PassportKit/Client/OAuthClient+Revocation.swift` | `OAuthClientTests` |
| DEV-1 | 8628 §3.1, §3.2 | MUST | Device authorization request sends `client_id` and optional `scope`; response needs `device_code`, `user_code`, a verification URI (`verification_url` alias accepted) and `expires_in`; `interval` defaults to 5 s | done | `Sources/PassportKit/Client/DeviceAuthorization.swift`, `OAuthClient+DeviceAuthorization.swift` | `DeviceAuthorizationTests` |
| DEV-7 | 8628 §3.2, §3.5 | MUST | Hostile numbers cannot trap: `interval` above 1 h is invalid, `slow_down` stops at 1 h, `expires_in` is clamped; verification URIs must be `https` (or loopback `http`) | done | `Sources/PassportKit/Client/DeviceAuthorization.swift`, `OAuthClient+DeviceAuthorization.swift` | `DeviceAuthorizationTests` |
| DEV-2 | 8628 §3.3 | MUST | `verification_uri_complete` is passed on verbatim; the library never opens a browser | done | `Sources/PassportKit/Client/DeviceAuthorization.swift` | `DeviceAuthorizationTests` |
| DEV-3 | 8628 §3.4 | MUST | Poll with `grant_type` device code and `device_code`, client authentication, no request after the deadline | done | `Sources/PassportKit/Client/OAuthClient+DeviceAuthorization.swift` | `DeviceAuthorizationTests` |
| DEV-4 | 8628 §3.5 | MUST | Wait the interval before every request; `authorization_pending` continues; `slow_down` adds 5 s permanently | done | `Sources/PassportKit/Client/OAuthClient+DeviceAuthorization.swift` | `DeviceAuthorizationTests` |
| DEV-5 | 8628 §3.5; 9110 §10.2.3 | SHOULD | Transport errors, 429 and 5xx back off exponentially (cap 30 s), larger `Retry-After` wins, reset after the next server answer | done | `Sources/PassportKit/Client/OAuthClient+DeviceAuthorization.swift` | `DeviceAuthorizationTests` |
| DEV-6 | 8628 §3.5 | MUST | `access_denied` and `expired_token` end polling; denial has no recovery, expiry needs reauthentication | done | `Sources/PassportKit/Client/OAuthClient+DeviceAuthorization.swift` | `DeviceAuthorizationTests` |
| AZC-1 | 6749 §4.1.1; 7636 §4.3 | MUST | Authorization request sends `response_type=code`, `client_id`, `redirect_uri`, `state`, `code_challenge`, `code_challenge_method=S256`, optional `scope`, repeated `resource`, `login_hint`, `prompt`; existing endpoint query preserved | done | `Sources/PassportKit/Client/OAuthClient+AuthorizationCode.swift` | `AuthorizationRequestTests` |
| AZC-2 | 6749 §10.12; 7636 §4.1 | MUST | `state` and verifier are 32 octets from the injected random source, base64url | done | `Sources/PassportKit/PKCE/PKCE.swift` | `AuthorizationRequestTests` |
| AZC-3 | 6749 §3.1.2; 8252 §7, §7.3, §8.3 | MUST | Redirect URI absolute, no fragment, `https`, private-use scheme or loopback `http`; callback matched on scheme, host, port, path; a callback with userinfo is rejected and a query on the registered redirect must appear in the callback | done | `Sources/PassportKit/Client/AuthorizationCallback.swift` | `AuthorizationRequestTests`, `AuthorizationCompletionTests` |
| AZC-4 | 6749 §4.1.2, §10.12 | MUST | `state` compared in constant time; mismatch rejected before anything else is trusted | done | `Sources/PassportKit/Client/OAuthClient+AuthorizationCode.swift` | `AuthorizationCompletionTests` |
| AZC-5 | 6749 §4.1.2.1 | MUST | `error`, `error_description`, `error_uri` become a typed error; `access_denied` has recovery `none` | done | `Sources/PassportKit/Client/OAuthClient+AuthorizationCode.swift` | `AuthorizationCompletionTests` |
| AZC-6 | 6749 §3.1 | MUST | Repeated response parameters are rejected | done | `Sources/PassportKit/Client/AuthorizationCallback.swift` | `AuthorizationCompletionTests` |
| AZC-7 | 6749 §4.1.3; 7636 §4.5 | MUST | Token request sends `grant_type=authorization_code`, `code`, `redirect_uri`, `code_verifier` and client authentication | done | `Sources/PassportKit/Client/OAuthClient+AuthorizationCode.swift` | `AuthorizationCompletionTests`, `AuthorizeTests` |
| AZC-8 | 6749 §4.1.2; 9700 §2.1.1 | MUST | A code is redeemed once: a pending authorization is single use and expires after a configurable lifetime (10 minutes by default) on the injected clock | done | `Sources/PassportKit/Client/PendingAuthorization.swift` | `AuthorizationCompletionTests` |
| AZC-9 | 9207 §2.4 | MUST | Response `iss` must equal the configured issuer by string comparison, also in error responses; a missing `iss` fails when `requiresIssuerInAuthorizationResponse` is set; `ClientConfiguration(metadata:authentication:)` sets it from `authorization_response_iss_parameter_supported` (RFC 9207 §3) | done | `Sources/PassportKit/Client/OAuthClient+AuthorizationCode.swift` | `AuthorizationCompletionTests` |
| AZC-10 | 8252 §4, §8 | SHOULD | The library never opens a browser; an app-supplied `UserAgent` presents the URL | done | `Sources/PassportKit/Client/AuthorizationRequest.swift` | `AuthorizeTests` |
| DISC-1 | 8414 §3.1 | MUST | Well-known URL inserts `/.well-known/oauth-authorization-server` between host and path, dropping a terminating slash; OpenID Connect style appends `/.well-known/openid-configuration` | done | `Sources/PassportKit/Discovery/Discovery.swift` | `DiscoveryTests` |
| DISC-2 | 8414 §3 | MUST | Metadata is fetched with `GET`, `Accept: application/json`; non-2xx and malformed responses are errors | done | `Sources/PassportKit/Discovery/Discovery.swift` | `DiscoveryTests` |
| DISC-3 | 8414 §3.3 | MUST | Metadata `issuer` must be identical to the requested issuer; expected-issuer and disabled modes are explicit | done | `Sources/PassportKit/Discovery/Discovery.swift` | `DiscoveryTests` |
| DISC-4 | 8414 §2 | MUST | Metadata members use their RFC names; unknown members are preserved and re-encoded | done | `Sources/PassportKit/Discovery/AuthorizationServerMetadata.swift` | `DiscoveryTests` |
| DISC-5 | 8414 §2; 6749 §3.2 | MUST | Endpoints derived from metadata need a token endpoint and TLS | done | `Sources/PassportKit/Configuration/Endpoints+Metadata.swift` | `DiscoveryTests` |
| CHAL-1 | 9110 §11.6.1; 6750 §3 | MUST | Challenges parsed from several header lines and several per line; auth-params as tokens or quoted strings with backslash escapes; commas inside quotes do not split | done | `Sources/PassportKit/HTTP/AuthenticationChallenge.swift` | `AuthenticationChallengeTests` |
| CHAL-2 | 9110 §11.1, §11.2 | MUST | Scheme and parameter names are case-insensitive and stored lower-cased | done | `Sources/PassportKit/HTTP/AuthenticationChallenge.swift` | `AuthenticationChallengeTests` |
| CHAL-3 | 9110 §11.2 | MUST | The `token68` form is recognised, including `=` padding | done | `Sources/PassportKit/HTTP/AuthenticationChallenge.swift` | `AuthenticationChallengeTests` |
| CHAL-4 | 6750 §3.1; 9449 §7.1 | MUST | `error`, `error_description`, `scope`, `algs` and other parameters are exposed verbatim; empty or malformed input never crashes | done | `Sources/PassportKit/HTTP/AuthenticationChallenge.swift` | `AuthenticationChallengeTests` |
| SES-1 | 6749 §6; 9700 §4.14 | MUST | Refresh tokens may rotate: every response carrying `refresh_token` is persisted before the access token is returned; an unsaveable one is kept in memory | done | `Sources/PassportKit/Session/TokenManager+Lane.swift` | `PersistenceTests` |
| SES-2 | 9700 §4.14; ADR 0005 | MUST | Operations that send the refresh token (refresh, exchange, revocation) run one at a time, each reading the token when it starts | done | `Sources/PassportKit/Session/RefreshLane.swift` | `LaneTests` |
| SES-3 | 8693 §2.1, §2.2.1 | MUST | A refresh-token subject is spent like a refresh grant and its rotated `refresh_token` is persisted; a `refresh_token` in an access-token-subject response is not the root grant and is ignored | done | `Sources/PassportKit/Session/TokenManager+Lane.swift`, `TokenManager+Targets.swift` | `PersistenceTests`, `ExpiryTests` |
| SES-4 | 6749 §3.3, §5.1; ADR 0004 | MUST | Every issued access token passes the acceptance policy before it is cached or returned; a rejection keeps the rotated refresh token and the session | done | `Sources/PassportKit/Session/TokenManager+Targets.swift` | `PersistenceTests` |
| SES-5 | 6749 §5.2 | MUST | Only `invalid_grant` for the refresh token (recovery `reauthenticate`) from a lane operation ends the session; a stale one from a replaced session is ignored | done | `Sources/PassportKit/Session/TokenManager+Lane.swift` | `LifecycleTests` |
| SES-6 | 6749 §5.1; 8693 §2.2.1 | SHOULD | Expiry from `expires_in`, else the default lifetime, else refresh on every use; derived tokens never outlive their subject | done | `Sources/PassportKit/Session/TokenManager+Targets.swift` | `ExpiryTests` |
| SES-7 | 7009 §2.1; ADR 0005 | SHOULD | Sign-out clears local state first, then revokes the refresh token in the lane, best effort within a time limit | done | `Sources/PassportKit/Session/TokenManager.swift` | `LifecycleTests` |
| SES-8 | 6750 §3.1 | SHOULD | A token reported as rejected is dropped only if it is still the cached one, so concurrent 401s cause one refresh | done | `Sources/PassportKit/Session/TokenCache.swift` | `LaneTests` |
| RES-1 | 6750 §2.1; 6750 §5.3 | MUST | Protected requests carry `Authorization: Bearer <token>`; no request is ever sent without a token, and a token is sent only over `https` or to a loopback host | done | `Sources/PassportKit/Authorization/RequestAuthorizer.swift` | `RequestAuthorizerTests`, `RequestAuthorizerConformanceTests` |
| RES-2 | 6750 §3.1 | MUST | 401 with `invalid_token` or no Bearer error: invalidate the token and retry once; a second 401 fails with `unauthorized` | done | `Sources/PassportKit/Authorization/RequestAuthorizer.swift` | `RequestAuthorizerTests`, `RequestAuthorizerConformanceTests` |
| RES-3 | 6750 §3.1 | MUST | `insufficient_scope` and every 403 are never refreshed; the session survives | done | `Sources/PassportKit/Authorization/RequestAuthorizer.swift` | `RequestAuthorizerTests`, `RequestAuthorizerConformanceTests` |
| RES-4 | 6750 §3.1 | SHOULD | Concurrent 401s for one token cause one refresh; a 401 after another caller refreshed retries with the new token without a refresh | done | `Sources/PassportKit/Authorization/RequestAuthorizer.swift` | `RequestAuthorizerConformanceTests` |
