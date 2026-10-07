# Implementation Plan

Milestones are ordered by dependency. Each one ends with `make check`
green, tests for everything it adds, `docs/rfc-matrix.md` rows updated,
and one or more commits. "Spec" refers to `docs/spec.md`.

| # | Milestone | Spec | Done when | Status |
|---|---|---|---|---|
| M0 | Package skeleton: `Package.swift`, three library targets, test targets, CI workflow, `make check` green | §2, §15 | `swift build` and `swift test` pass; CI runs lint, macOS tests, Linux tests | done |
| M1 | Foundations: `Secret`, `ScopeSet`, `AdditionalParameters`, `JSONValue`, `GrantType`, `TokenTypeIdentifier`, seams, form encoding, HTTP types, `URLSessionTransport`, `PassportError` + classification, `TokenResponse` parsing, PKCE + SHA-256 | §3–§7 | unit tests incl. RFC 7636 Appendix B, form-encoding vectors, error classification table, redaction | done |
| M2 | `OAuthClient`: refresh, client credentials, exchange, revoke, extension grant, client authentication, observer events | §5, §8 | request/response tests against a recording transport | done |
| M3 | Device authorization grant with poller | §8 | poller tests with `ManualClock`: pending, `slow_down`, backoff, expiry, denial, cancellation | done |
| M4 | Authorization code + PKCE, `AuthorizationUserAgent`, callback validation incl. `iss`; discovery + issuer validation; `AuthenticationChallenge` parser | §8, §10, §11 | tests for every callback check, RFC 8414 URL construction, challenge corpus | done |
| M5 | `PassportKitTesting`: `FakeAuthorizationServer`, `ManualClock`, `ManualWallClock`, `SequenceRandomSource`, `RecordingTransport` | §14 | fake server covers every endpoint and toggle; self-tests | done |
| M6 | `TokenManager`, `CredentialStore`, `InMemoryCredentialStore`, acceptance policies, events | §9 | one conformance test per invariant against the fake server | done |
| M7 | `RequestAuthorizer` | §10 | 401/403/`insufficient_scope` matrix, never unsigned, single refresh for concurrent 401s | done |
| M8 | `PassportKitApple`: Keychain store, `ASWebAuthenticationSession` agent, loopback agent | §13 | Keychain round trip with unique service, loopback agent end-to-end against `URLSession` | done |
| M9 | Real-server verification: example executable; scenario runs against a local open-source authorization server in Docker and against public metadata endpoints | §2 | documented runs, issues found fed back as tests | done |
| M10 | Hardening: redaction canary test, determinism grep in CI, DocC, README quick start, review passes, retrospective | §12, §15 | reviewers report no open findings | implemented; review pending |

## Next

Ideas that came out of the pre-release API review and were left out on
purpose. None of them blocks the first release; each needs a design and an
ADR before work starts.

- **Client credentials target in `TokenManager`.** Cache and coalesce
  machine-to-machine tokens (RFC 6749 §4.4) the way user tokens are, with
  a target derivation of their own and no refresh token or session.
- **`OAuthClient(issuer:)`.** An asynchronous convenience that runs
  discovery (RFC 8414) and builds the configuration, so the common case
  is one call.
- **Presentation options for `AuthorizationUserAgent`.** A struct that
  carries per-request choices, such as an ephemeral browser session or a
  presentation anchor, instead of adding parameters to `present`.
- **A `Dependencies` struct for the seams.** Bundle the transport, clocks,
  random source and observer that `OAuthClient` takes as separate
  parameters, so they can be passed around and extended as one value.
