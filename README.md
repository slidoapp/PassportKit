# PassportKit

PassportKit is an OAuth 2.0 client library for Swift 6. It works against any standards-compliant authorization
server and has no vendor-specific behavior: server quirks are handled through the RFCs it implements and a few
documented extension points. It covers signing a person in (authorization code with PKCE, or the device flow),
keeping the session safe while refresh tokens rotate, and signing requests to protected resources. Time, randomness
and the HTTP transport are injected, so every flow can be tested offline, and secrets never appear in logs,
descriptions or errors.

> **Status:** pre-1.0. The API may change between minor versions until 1.0.

## Features

| Feature | Specification |
|---|---|
| Authorization code grant with PKCE (`S256`), `state`, exact redirect matching | RFC 6749, RFC 7636, RFC 9700 |
| Issuer identification in authorization responses | RFC 9207 |
| Device authorization grant with interval, `slow_down` and back-off handling | RFC 8628 |
| Refresh tokens with rotation, coalesced refreshes and persist-before-use | RFC 6749 §6, RFC 9700 §4.14 |
| Client credentials and extension grants | RFC 6749 §4.4, §4.5 |
| Token exchange for other audiences and resources | RFC 8693 |
| Resource indicators | RFC 8707 |
| Authorization server metadata discovery | RFC 8414 |
| Token revocation on sign-out | RFC 7009 |
| Bearer token requests with a single retry after a 401 | RFC 6750 |
| Native app redirects: `ASWebAuthenticationSession`, loopback | RFC 8252 |
| Granted scope on every token, and an acceptance hook before a token is used | RFC 6749 §3.3, §5.1 |
| Keychain credential storage (Apple platforms) | |
| A fake authorization server and test clocks | |

[docs/rfc-matrix.md](docs/rfc-matrix.md) traces every requirement to its code and test.

## Requirements

- Swift 6.2 or later (Xcode 26 or later).
- `PassportKit` (the core) builds on macOS 14, iOS 17, tvOS 17, watchOS 10, visionOS 1 and Linux.
- `PassportKitApple` (Keychain, `ASWebAuthenticationSession`, loopback listener) needs an Apple platform.

## Installation

Add the package to `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/OWNER/PassportKit.git", from: "0.1.0")
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "PassportKit", package: "PassportKit"),
        .product(name: "PassportKitApple", package: "PassportKit"),  // Apple platforms only
    ]),
    .testTarget(name: "MyAppTests", dependencies: [
        .product(name: "PassportKitTesting", package: "PassportKit")
    ]),
]
```

There is no release yet; replace `OWNER` and the version once one exists.

## Quick start

Sign in with the device flow, keep the session, and call an API:

```swift
import PassportKit

let issuer = URL(string: "https://as.example.com")!
let metadata = try await Discovery.fetchMetadata(issuer: issuer)
let client = try OAuthClient(
    configuration: ClientConfiguration(metadata: metadata, authentication: .publicClient(clientID: "my-app")))

// 1. Sign in. Show the code, then wait for the person to approve.
let authorization = try await client.beginDeviceAuthorization(scope: ["openid", "offline_access"])
print("Open \(authorization.verificationURI) and enter \(authorization.userCode)")
let tokens = try await client.completeDeviceAuthorization(authorization)

// 2. Keep the session: the manager stores, rotates and refreshes.
let account = CredentialAccount(service: "com.example.app", account: "default")
let manager = TokenManager(client: client, store: InMemoryCredentialStore(), account: account)
try await manager.signIn(with: tokens, requestedScope: ["openid", "offline_access"])

// 3. Call an API. The authorizer adds the token and refreshes once if the server rejects it.
let authorizer = RequestAuthorizer(manager: manager)
let request = URLRequest(url: URL(string: "https://api.example.com/items")!)
let (data, response) = try await authorizer.data(for: request, session: URLSession(configuration: .ephemeral))
```

Use `KeychainCredentialStore` from `PassportKitApple` instead of `InMemoryCredentialStore` in an app. The
`passportkit-example` executable runs the device and code flows against a server you name.

## Documentation

The DocC catalogs are in `Sources/*/*.docc` and are published on the Swift Package Index. Start here:

- [Getting started](Sources/PassportKit/PassportKit.docc/GettingStarted.md)
- [Sessions and token targets](Sources/PassportKit/PassportKit.docc/SessionsAndTokenTargets.md)
- [Resource access and scopes](Sources/PassportKit/PassportKit.docc/ResourceAccessAndScopes.md): why a
  200 response is not proof of access
- [Error handling](Sources/PassportKit/PassportKit.docc/ErrorHandling.md)
- [Native app redirects](Sources/PassportKit/PassportKit.docc/NativeAppRedirects.md)
- [Testing](Sources/PassportKit/PassportKit.docc/Testing.md)

Design documents: [specification](docs/spec.md), [architecture](docs/architecture.md),
[security model](docs/security-model.md) and the [decision records](docs/decisions/). Run `make docs` to build
the DocC archives locally.

## Testing your app

The `PassportKitTesting` library contains `FakeAuthorizationServer`, an in-process authorization server and
protected resource that plugs in as the HTTP transport, plus `ManualClock`, `FixedWallClock` and
`RecordingTransport`. Add it to test targets only. See the Testing article above.

## Contributing

Issues and pull requests are welcome; read [CONTRIBUTING.md](CONTRIBUTING.md) first. Report vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

## License

PassportKit is available under the MIT license. See [LICENSE](LICENSE) for details.
