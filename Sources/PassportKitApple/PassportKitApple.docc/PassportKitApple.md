# ``PassportKitApple``

Apple platform adapters for PassportKit: Keychain storage and the
user agents that complete a sign-in in the system browser.

## Overview

`PassportKit` itself imports only Foundation so that it builds on Linux. This
module adds what needs Apple frameworks:

- ``KeychainCredentialStore`` stores the `Credential` of a
  `TokenManager` in the Keychain. Items are never
  synchronizable, because a refresh token must not move between devices.
- ``WebAuthenticationSessionUserAgent`` presents the authorization page in
  an `ASWebAuthenticationSession`.
- ``LoopbackRedirectListener`` and ``LoopbackUserAgent`` receive the
  redirect on `127.0.0.1` (RFC 8252 §7.3), for macOS tools and apps.

Choosing between the user agents is covered in
the "Native app redirects" article of PassportKit.

## Topics

### Credential storage

- ``KeychainCredentialStore``

### System browser sessions

- ``WebAuthenticationSessionUserAgent``

### Loopback redirects

- ``LoopbackRedirectListener``
- ``LoopbackUserAgent``
