# Architecture

Invariants and boundaries, not an inventory of types: the exact API is in `docs/spec.md`. If code and this document
disagree, fix one of them in the same change. Changing a module boundary needs an ADR.

## Modules

| Module | Purpose | May import |
|---|---|---|
| `PassportKit` | Grants, token model, session actor, credential stores (in-memory and Keychain), errors, metadata discovery, request authorization, and the user agents (`ASWebAuthenticationSession`, loopback listener). macOS 14 and iOS 17 only (ADR 0011) | Foundation, CryptoKit, swift-http-types, swift-log, SwiftKeychain, Apple frameworks |
| `PassportKitTesting` | Fake authorization server, test clocks and a recording transport; public so consumers can test against it | `PassportKit`, swift-http-types |

Testing depends on the core, never the reverse. External dependencies follow ADR 0009. `passportkit-example`
(`Sources/passportkit-example`) is an executable, not a product.

## Source layout

`Sources/PassportKit/<Folder>`:

| Folder | Holds |
|---|---|
| `Core` | Value types and seams: `Secret`, `ScopeSet`, `AdditionalParameters`, `JSONValue`, `GrantType`, token type identifiers, `WallClock`, `RandomSource`, wire-name constants |
| `Configuration` | `ClientConfiguration`, `ClientAuthentication`, `Endpoints`, loopback host rules |
| `Client` | `OAuthClient` (stateless protocol operations, one file per grant family), request and pending-authorization types, form requests |
| `Tokens` | `TokenResponse` and its parsing |
| `Errors` | `PassportError`, its codes, classification and recovery mapping |
| `HTTP` | `HTTPTransport`, `URLSessionTransport`, redirect policy, form encoding, `AuthenticationChallenge`, redaction helpers |
| `Discovery` | `Discovery` and `AuthorizationServerMetadata` (RFC 8414) |
| `PKCE` | Verifier, S256 challenge, base64url |
| `Session` | `TokenManager` and everything it owns: refresh lane, token cache, acceptance policies, events, `Credential`, `CredentialStore`, `InMemoryCredentialStore` |
| `Authorization` | `RequestAuthorizer` and `RetryDecision` |
| `Storage` | `KeychainCredentialStore` |
| `UserAgents` | `WebAuthenticationSessionUserAgent`, `LoopbackRedirectListener`, `LoopbackUserAgent` |
| `Observability` | `PassportObserver`, `PassportEvent`, logging keys |

Tests mirror this: `PassportKitTests` (units), `PassportKitTestingTests` (the fake server), `ConformanceTests`
(scenarios), `IntegrationTests` (real server). See `docs/testing.md`.

## Concurrency model

- Public types are `Sendable`. Mutable session state lives in actors.
- Refresh is single-flight per session: concurrent callers await the same in-flight refresh. Operations that send the
  refresh token (refresh, token exchange with a refresh-token subject, revocation) are serialized per session in one
  FIFO lane, because servers may rotate refresh tokens and allow little or no reuse. The lane reads the token when a
  turn starts, not when it is queued.
- A rotated refresh token is persisted before the new access token is handed out. Every change of the stored
  credential goes through one FIFO, so a slow store cannot apply an older save after a newer delete.
- A result that arrives after the session was cleared or replaced is discarded (generation check), never written back.
  Each session has its own lane, so a stuck request of an ended session cannot block the next one. A sign-out's
  revocation runs on the ended session's lane and sends the newest refresh token it learned of, including one issued
  to a request that finished after the sign-out (ADR 0007).
- Everything that waits on application code or the network is bounded or abandonable: the acceptance policy has a time
  limit, revocation has a time limit, and a time limit does not wait for work that ignores cancellation.
- Every long-running operation (device polling, interactive authorization, refresh) honours task cancellation.

## Token lifecycle invariants

The full list with its edge cases is `docs/spec.md` §9. The ones every change must keep:

1. A token response becomes current only after the acceptance policy accepted it. The rotated refresh token from the
   same response is persisted even if the policy rejects the access token.
2. Tokens are bound to the resource indicators they were requested for (RFC 8707) and never reused for another target.
3. The granted scope is always recorded: the response `scope`, or the requested scope when the response omits it
   (RFC 6749 §5.1).
4. Only `invalid_grant` on a refresh (or the expiry of a grant that has no refresh token) ends a session. Resource-level
   denials (`access_denied`, `invalid_target`, policy rejection, `insufficient_scope`) are reported to the caller and
   leave the session intact.

## Extension points

Extension points are the only place where server-specific behaviour enters. Each one is justified by an ADR.

- HTTP transport (default `URLSession`). Its currency types are swift-http-types' `HTTPRequest`, `HTTPResponse` and
  `HTTPFields`, with the body as `Data` beside them (ADR 0010).
- Credential storage (default: none; `KeychainCredentialStore` and `InMemoryCredentialStore` are provided).
- Clocks and random source.
- Token acceptance policy.
- Additional request parameters and headers per request.
- Logging (swift-log `Logger` parameters) and typed observer events. Secrets are never part of either.

## What the library deliberately does not know

- The meaning of any scope or resource beyond the RFCs.
- Resource-server business semantics, such as which endpoint needs which scope.
- Server-specific error codes or response fields: unknown fields are preserved for the app, never interpreted.
