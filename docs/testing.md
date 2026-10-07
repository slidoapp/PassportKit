# Testing

## Layers

| Layer | Location | What it covers |
|---|---|---|
| Unit | `Tests/PassportKitTests` | Request building, response and error parsing, PKCE, form encoding, `WWW-Authenticate` parsing, metadata parsing |
| Conformance | `Tests/ConformanceTests` | End-to-end flows against the fake authorization server: rotation, coalesced refresh, device polling, token exchange, resource indicators, error handling |
| Apple adapters | `Tests/PassportKitAppleTests` | Keychain storage, redirect handling; macOS only |

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

## Fixtures

- Golden HTTP exchanges live under `Tests/Fixtures`.
- Fixtures are sanitised: no real tokens, no real hostnames
  (`as.example.com`, `api.example.com`).
- Do not edit an existing fixture to make a test pass. Add a new fixture
  and explain why in the commit body.
