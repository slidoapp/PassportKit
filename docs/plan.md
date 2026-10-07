# Implementation Plan

Milestones are ordered by dependency. Each one ends with `make check`
green, tests for everything it adds, `docs/rfc-matrix.md` rows updated,
and one or more commits. "Spec" refers to `docs/spec.md`.

| # | Milestone | Spec | Done when |
|---|---|---|---|
| M0 | Package skeleton: `Package.swift`, three library targets, test targets, CI workflow, `make check` green | §2, §15 | `swift build` and `swift test` pass; CI runs lint, macOS tests, Linux tests |
| M1 | Foundations: `Secret`, `ScopeSet`, `AdditionalParameters`, `JSONValue`, `GrantType`, `TokenTypeIdentifier`, seams, form encoding, HTTP types, `URLSessionTransport`, `PassportError` + classification, `TokenResponse` parsing, PKCE + SHA-256 | §3–§7 | unit tests incl. RFC 7636 Appendix B, form-encoding vectors, error classification table, redaction |
| M2 | `OAuthClient`: refresh, client credentials, exchange, revoke, extension grant, client authentication, observer events | §5, §8 | request/response tests against a recording transport |
| M3 | Device authorization grant with poller | §8 | poller tests with `ManualClock`: pending, `slow_down`, backoff, expiry, denial, cancellation |
| M4 | Authorization code + PKCE, `UserAgent`, callback validation incl. `iss`; discovery + issuer validation; `AuthenticationChallenge` parser | §8, §10, §11 | tests for every callback check, RFC 8414 URL construction, challenge corpus |
| M5 | `PassportKitTesting`: `FakeAuthorizationServer`, `ManualClock`, `FixedWallClock`, `SequenceRandomSource`, `RecordingTransport` | §14 | fake server covers every endpoint and toggle; self-tests |
| M6 | `TokenManager`, `CredentialStore`, `InMemoryCredentialStore`, acceptance policies, events | §9 | one conformance test per invariant against the fake server |
| M7 | `RequestAuthorizer` | §10 | 401/403/`insufficient_scope` matrix, never unsigned, single refresh for concurrent 401s |
| M8 | `PassportKitApple`: Keychain store, `ASWebAuthenticationSession` agent, loopback agent | §13 | Keychain round trip with unique service, loopback agent end-to-end against `URLSession` |
| M9 | Real-server verification: example executable; scenario runs against a local open-source authorization server in Docker and against public metadata endpoints | §2 | documented runs, issues found fed back as tests |
| M10 | Hardening: redaction canary test, determinism grep in CI, DocC, README quick start, review passes, retrospective | §12, §15 | reviewers report no open findings |
