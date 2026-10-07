# Testing

## Layers

| Layer | Location | What it covers |
|---|---|---|
| Unit | `Tests/PassportKitTests` | Request building, response and error parsing, PKCE, form encoding, `WWW-Authenticate` parsing, metadata parsing |
| Conformance | `Tests/ConformanceTests` | End-to-end flows against the fake authorization server: rotation, coalesced refresh, device polling, token exchange, resource indicators, error handling, and the redaction canary |
| Integration | `Tests/IntegrationTests` | The real flows against a local `oidc-provider` server (`Tools/integration-server`): discovery, authorization code with PKCE and `iss`, device flow, refresh rotation and reuse rejection, token exchange, the underscoped-200 case, client credentials, revocation, Keychain; macOS |
| Apple adapters | `Tests/PassportKitAppleTests` | Keychain storage, redirect handling; macOS only |

## Integration tests

The conformance tests prove the library against our model of a server; the
integration tests prove that model against an independent implementation.
They are skipped unless `PASSPORTKIT_INTEGRATION_ISSUER` is set, so
`make check` stays offline.

```sh
make integration   # needs Node.js; the first run installs the server with `npm ci`
```

The target starts the server on a free port with a 60 s access token
lifetime, waits until it answers, runs `swift test --filter IntegrationTests`
and stops the server on exit. To debug against a server you started yourself
(see `Tools/integration-server/README.md`):

```sh
PASSPORTKIT_INTEGRATION_ISSUER=http://localhost:9400 swift test --filter IntegrationTests
```

Rules specific to this layer:

- Each test signs in with its own client and session; no test depends on
  another, so they run in parallel.
- These tests use the real clock and network. The device flow takes a little
  over 5 s because the server's polling interval is 5 s. Token expiry is
  forced without sleeping by setting `minimumTokenLifetime` above the
  server's token lifetime, which makes every cached token stale.
- The server drops `offline_access` unless the authorization request has
  `prompt=consent`, and a refresh grant can only name resources that the
  authorization granted, so the tests request both resources up front.
- The authorization code tests use a user agent that follows the server's
  redirects with `URLSession` and stops at the redirect URI.
- A scenario that fails because of a library defect is wrapped in
  `withKnownIssue` with a pointer to the defect, not deleted.

CI runs the same target in the `integration` job.

## Redaction canary

`RedactionCanaryTests` runs every flow against the fake server with a client
secret and every token, code, verifier and device code that crosses the wire
treated as a canary. Error paths make the server repeat the secrets it was
sent in `error_description` and in `WWW-Authenticate`. The test then renders
every public value and error (`String(describing:)`, `String(reflecting:)`,
`dump`, `localizedDescription`) and every `PassportEvent` and `SessionEvent`,
and fails if any canary appears. A new flow or public value that holds a
secret is added to it. `Foundation`'s own `URLRequest` is excluded: it prints
the headers it carries.

## Documentation samples

The code in the DocC articles is compiled in
`Tests/ConformanceTests/DocumentationSnippets.swift` (and, for Apple adapters,
`Tests/PassportKitAppleTests/DocumentationSnippets.swift`). They are never run; they keep the samples
in step with the API. Change both together.

## Rules

- Swift Testing (`import Testing`). Parameterise over RFC example vectors
  (for example RFC 7636 Appendix B) where they exist.
- No network access and no sleeps. Time comes from the injected clock.
- Tests are independent and run in parallel. No shared global state.
- Every secret-holding type has a test that its descriptions are redacted.

## Fake authorization server

`PassportKitTesting` provides an in-process fake authorization server
plugged in through the HTTP transport extension point. A scenario
scripts the server's responses and asserts on the requests it received.
Server quirks are modelled as generic scenarios (for example "refresh
with a resource indicator returns 200 with narrowed scope"), never as
named vendors.

### Seams of the fake server

Two hooks control expiry and response timing without sleeping:

- `expire(token:)` makes the server treat one issued token as expired as of
  the injected wall clock's current time, without moving that clock. Use it
  to test a rejection of a token the client still believes is fresh.
- `Controls.responseDelay` holds back the answer to a request, on the
  injected `Clock`, after the server has already handled it (tokens have
  rotated). Use it to test coalescing, cancellation while a request is in
  flight, and the revocation time limit. An override delay, in contrast,
  delays the request before it takes effect.

## Fixtures

- Golden HTTP exchanges live under `Tests/Fixtures`.
- Fixtures are sanitised: no real tokens, no real hostnames
  (`as.example.com`, `api.example.com`).
- Do not edit an existing fixture to make a test pass. Add a new fixture
  and explain why in the commit body.
