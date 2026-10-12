# 0002. Package layout and toolchain

- Status: accepted; the dependency and logging bullets are superseded by
  [0009](0009-external-dependencies.md), the product and Linux parts by
  [0011](0011-apple-platforms-only.md)
- Date: 2026-10-07

## Context

The library must serve Apple apps (including a macOS 14 host that cannot
require macOS 15), command-line tools and server-side Swift. ~~Command-line
tools and server-side Swift on Linux~~ are out of scope since
[0011](0011-apple-platforms-only.md). Every
third-party dependency is resolved by every consumer, even when a target
uses it only on some platforms.

## Decision

- SwiftPM only, `swift-tools-version: 6.2`, Swift 6 language mode.
- ~~Three products: `PassportKit` (core, Foundation only, builds on Linux),
  `PassportKitApple` (Keychain, `ASWebAuthenticationSession`, loopback
  listener) and `PassportKitTesting` (fake authorization server and test
  seams).~~ Superseded by [0011](0011-apple-platforms-only.md): two
  products, `PassportKit` (including the former Apple module, Apple
  platforms only) and `PassportKitTesting`.
- ~~No third-party runtime dependencies. SHA-256 for PKCE uses CryptoKit
  when available and a small tested implementation otherwise.~~
  Superseded by [0009](0009-external-dependencies.md).
- Minimum platforms: macOS 14, iOS 17, tvOS 17, watchOS 10, visionOS 1.
- ~~Logging is an observer protocol; apps bridge it to their logger.~~
  Superseded by [0009](0009-external-dependencies.md): swift-log is used
  in addition to the observer.

## Consequences

Consumers pay for nothing they do not import (see 0009 for what they now
resolve). Features that need real
cryptography (DPoP) will need a separate product or package trait later.
`Synchronization.Mutex` is unavailable at the macOS 14 floor, so shared
state lives in actors and, in classes, behind `OSAllocatedUnfairLock`
([0011](0011-apple-platforms-only.md)).
