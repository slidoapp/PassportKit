# 0002. Package layout and toolchain

- Status: accepted
- Date: 2026-10-07

## Context

The library must serve Apple apps (including a macOS 14 host that cannot
require macOS 15), command-line tools and server-side Swift. Every
third-party dependency is resolved by every consumer, even when a target
uses it only on some platforms.

## Decision

- SwiftPM only, `swift-tools-version: 6.2`, Swift 6 language mode.
- Three products: `PassportKit` (core, Foundation only, builds on Linux),
  `PassportKitApple` (Keychain, `ASWebAuthenticationSession`, loopback
  listener) and `PassportKitTesting` (fake authorization server and test
  seams).
- No third-party runtime dependencies. SHA-256 for PKCE uses CryptoKit
  when available and a small tested implementation otherwise.
- Minimum platforms: macOS 14, iOS 17, tvOS 17, watchOS 10, visionOS 1.
- Logging is an observer protocol; apps bridge it to their logger.

## Consequences

Consumers pay for nothing they do not import. Features that need real
cryptography (DPoP) will need a separate product or package trait later.
`Synchronization.Mutex` is unavailable at the macOS 14 floor, so shared
state lives in actors.
