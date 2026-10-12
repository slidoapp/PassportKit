# 0009. External dependencies

- Status: accepted
- Date: 2026-10-12
- Supersedes: the dependency bullet and the logging bullet of
  [0002](0002-package-layout-and-toolchain.md)

## Context

ADR 0002 ruled out third-party runtime dependencies to keep consumers'
dependency graphs small. That left PassportKit maintaining code that
well-maintained packages already provide: a SHA-256 implementation with a
CryptoKit switch, and an observer protocol that every app had to bridge
to its logger by hand. Cryptography written in-house is a liability in a
security library, and server-side Swift apps already log through
swift-log.

## Decision

Prefer well-maintained packages from Apple, the Swift Server Workgroup
(SSWG) or the Swift project over hand-written code for cryptography,
logging and protocol currency types. A dependency is accepted when:

- it is maintained by Apple or the SSWG, or is equally actively maintained;
- it builds on Linux as well as Apple platforms;
- its license is permissive (Apache 2.0, MIT, BSD);
- it brings no large transitive dependency tree;
- it follows semantic versioning, and we depend on it with `from:` so
  that a major version is the only range boundary.

Each dependency is linked only into the target that needs it.

### Current dependencies

| Package | Product | Used by | Why |
|---|---|---|---|
| [swift-crypto](https://github.com/apple/swift-crypto) `"3.15.1"..<"6.0.0"` | `Crypto` | `PassportKit`, `PassportKitTesting` | SHA-256 for PKCE S256 (RFC 7636 §4.2). Re-exports CryptoKit on Apple platforms and uses BoringSSL elsewhere. The fake authorization server calls it directly, not PassportKit's code path, so it still checks the client independently. |
| [swift-log](https://github.com/apple/swift-log) `from: 1.6.0` | `Logging` | `PassportKit`, `PassportKitApple` | The `logger:` parameters. A logger labelled `PassportKit` uses whatever `LoggingSystem.bootstrap` the host configured. `PassportObserver` stays the channel for typed events. |
| [SwiftKeychain](https://github.com/slidoapp/SwiftKeychain) `.upToNextMinor(from: "2.1.0")` | `SwiftKeychain` | `PassportKitApple` | The Keychain wrapper the Slido OAuth stack already uses; `KeychainCredentialStore` is built on it. Adopted with a known issue, below. |

`SystemRandomSource` stays: `SystemRandomNumberGenerator` is the standard
library's cryptographically secure generator on every supported platform,
and swift-crypto offers nothing clearer.

### Adopted with a known issue: SwiftKeychain

On `errSecDuplicateItem`, `Keychain.insertItemWithAttributes` deletes the
existing item and adds it again. If the second step fails (device locked,
a denied prompt, an entitlement problem) or the process dies in between,
the stored credential is lost. With refresh token rotation the replaced
token is already invalid, so the user must sign in again. Stores writing
the same item at once can fail the same way; the test that races eight
stores is recorded as a known issue. The payload is also archived with
`try?`, so an encoding failure silently stores no data. Two further
limits: SwiftKeychain cannot target the data protection keychain, so
`useDataProtectionKeychain` was removed, and its delete and fetch queries
include the accessibility class, so an item stored with another class is
not found.

Planned fix: an upstream change that updates first and adds only on
`errSecItemNotFound`, with typed errors. Until then the single-store
write path (serialized by the store's queue) is the supported use, and
the issue is listed under Known limits in the security model.

### Rejected candidates

- **pointfree swift-clocks:** its `TestClock` lacks the equivalent of
  `ManualClock.advanceToNextSleeper`, which the race tests rely on.
- **swift-async-algorithms:** no stable multicast, which `TokenManager.events`
  needs.
- **`Synchronization.Mutex`:** needs macOS 15; the floor is macOS 14
  (ADR 0002), so shared state stays in actors and lock-guarded classes.
- **swift-nio or FlyingFox for the loopback listener:** too heavy for
  accepting one request; the Network framework listener is enough.

## Consequences

Consumers resolve swift-crypto, swift-log and, on Apple platforms,
SwiftKeychain even when they use a small part of the package; the host
app already resolves swift-log. Hand-written SHA-256 and its tests are
gone. Logging is an additional channel that must follow the redaction
rules in `docs/security-model.md`; the redaction canary test captures log
output to enforce them. Adding a dependency now needs this ADR's criteria
checked and its row added to the table above.
