# PassportKit

A modern OAuth 2.0 client library for Swift, built for Swift 6 and structured concurrency.

> **Status:** early development. The API is not stable and there is no release yet.

## Goals

- `async`/`await` API with strict concurrency checking and `Sendable` types throughout
- Standards first: authorization code with PKCE, device authorization, refresh tokens,
  token exchange, resource indicators, and authorization server metadata
- Safe token lifecycle: coalesced refreshes, refresh token rotation, cancellation, and
  pluggable secure storage
- No vendor-specific behavior in the core; provider quirks are handled through explicit
  extension points
- Secrets never appear in logs or descriptions

## Installation

PassportKit is distributed with Swift Package Manager. Installation instructions will be
added with the first release.

## Contributing

Issues and pull requests are welcome. Contribution guidelines will follow.

## License

PassportKit is available under the MIT license. See [LICENSE](LICENSE) for details.
