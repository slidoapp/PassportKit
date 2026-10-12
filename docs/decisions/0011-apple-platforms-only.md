# 0011. Apple platforms only

- Status: accepted
- Date: 2026-10-12
- Supersedes: the product, Linux and platform parts of
  [0002](0002-package-layout-and-toolchain.md), the Linux criterion and
  swift-crypto row of [0009](0009-external-dependencies.md), and the Linux
  notes of [0010](0010-http-types.md)

## Context

ADR 0002 wanted a core that builds on Linux, so PassportKit was split in
two: a portable core and an Apple adapter module. Every known consumer is
an Apple app. Linux support cost more than it returned:

- a second module (`PassportKitApple`), two imports in every app, two DocC
  catalogs and `package` access for names shared across the boundary;
- swift-crypto, resolved by every consumer, only to hash the PKCE verifier
  where CryptoKit is missing;
- `NSLock` next to guarded state, which the compiler cannot check, so each
  such class was `@unchecked Sendable` with a justifying comment;
- `canImport(FoundationNetworking)` imports, and tests restructured around
  swift-corelibs-foundation, which traps when a `URLProtocol` stub reports
  a redirect;
- a CI job that could not be reproduced locally.

## Decision

PassportKit supports Apple platforms only: macOS 14, iOS 17, tvOS 17,
watchOS 10 and visionOS 1 (unchanged minimums).

- Two products: `PassportKit` (everything, including `KeychainCredentialStore`,
  `WebAuthenticationSessionUserAgent`, `LoopbackRedirectListener` and
  `LoopbackUserAgent`) and `PassportKitTesting`. `PassportKitApple` is gone.
- SHA-256 comes from CryptoKit; swift-crypto is removed. The fake
  authorization server still hashes with CryptoKit and encodes base64url
  itself, so it does not echo the client's code path.
- Shared mutable state in classes lives inside an `OSAllocatedUnfairLock`
  (macOS 13, iOS 16), which keeps those classes `Sendable` without
  `@unchecked`. `Synchronization.Mutex` still needs macOS 15.
- Platform guards remain only where a framework is missing:
  `ASWebAuthenticationSession` does not exist on tvOS and watchOS, and the
  loopback listener and agent exist on macOS, iOS and visionOS, where a
  browser can reach `127.0.0.1` on the same device. On tvOS and watchOS
  the device flow is the way to sign in.
- No Linux CI job; `make check` on macOS is the gate.

## Consequences

Apps add one product and resolve fewer packages. Locking is checked by the
compiler, and local `make check` equals CI. The library cannot be used by
server-side Swift or command-line tools on Linux, and the Linux CI signal
for the portable parts is gone.

To revisit: Linux support needs a portable SHA-256 (swift-crypto behind
`#if canImport(CryptoKit)`), FoundationNetworking imports, a lock that
does not need `os` (a mutex from `Synchronization` once macOS 15 is the
floor, or `NSLock`), and a Linux CI job; the Apple-only types can stay in
`PassportKit` behind `#if canImport(...)` or move back to a separate
module. Weigh that cost against a concrete consumer.
