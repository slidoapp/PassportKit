# Architecture

This document records invariants and boundaries, not an inventory of
types. If code and this document disagree, fix one of them in the same
change.

> Status: the module layout below is the planned target. It becomes
> binding once the first `Package.swift` lands.

## Modules

| Module | Purpose | May import |
|---|---|---|
| `PassportKit` | Core: grants, token model, session actor (refresh coordination), credential store protocol and in-memory store, errors, metadata discovery, request authorization | Foundation only; must build on Linux |
| `PassportKitApple` | Apple adapters: Keychain storage, `ASWebAuthenticationSession`, loopback redirect listener | `PassportKit`, Apple frameworks |
| `PassportKitTesting` | Fake authorization server and test clocks; public so consumers can test against it | `PassportKit` |

Dependencies point inward only: adapters and testing depend on the core,
never the reverse. The core has no third-party runtime dependencies.

## Concurrency model

- Public types are `Sendable`. Mutable session state lives in actors.
- Refresh is single-flight per session: concurrent callers await the
  same in-flight refresh. Refresh-token-consuming operations (refresh,
  token exchange with a refresh-token subject, revocation) are serialized
  per session, because servers may rotate refresh tokens and allow little
  or no reuse.
- A rotated refresh token is persisted before the new access token is
  handed out.
- Results that arrive after the session was cleared or replaced are
  discarded (generation check), never written back.
- Every long-running operation (device polling, interactive
  authorization, refresh) honours task cancellation.

## Token lifecycle invariants

1. A token response becomes current only after it passes the app-supplied
   acceptance hook. The rotated refresh token from the same response is
   persisted even if the hook rejects the access token.
2. Tokens are bound to the resource indicator(s) they were requested for
   (RFC 8707) and never reused for another resource.
3. Granted scope is always recorded: the response `scope`, or the
   requested scope when the response omits it (RFC 6749 §5.1).
4. Only `invalid_grant` on refresh ends a session. Resource-level denials
   (`access_denied`, `invalid_target`, acceptance-hook rejection,
   `insufficient_scope`) are reported to the caller and leave the session
   intact.

## Extension points

Extension points are the only place where server-specific behaviour
enters. Each one is justified by an ADR.

- HTTP transport (default: `URLSession`)
- Credential storage (default: Keychain on Apple platforms)
- Clock and random source
- Token acceptance hook
- Additional request parameters and headers per request
- Error classification for resource-server responses
- Logging/observability events (secrets are never part of an event)

## What the library deliberately does not know

- The meaning of any scope or resource beyond the RFCs.
- Resource-server business semantics (which endpoint needs which scope).
- Server-specific error codes or response fields; unknown fields are
  preserved for the app, never interpreted.
