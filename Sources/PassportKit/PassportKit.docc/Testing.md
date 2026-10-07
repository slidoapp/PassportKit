# Testing

The `PassportKitTesting` library runs every flow in this package without a
network and without sleeping.

## Why a fake server

Because the library takes its HTTP transport, clocks and randomness as
parameters, a test can replace all of them. `FakeAuthorizationServer` is an
in-process authorization server and protected resource that plugs in as the
``HTTPTransport``. It serves discovery, authorization, token, device
authorization and revocation endpoints and a bearer-protected resource, and
records every request.

Add the library to your test target only:

```swift
.testTarget(name: "MyAppTests", dependencies: [
    .product(name: "PassportKit", package: "PassportKit"),
    .product(name: "PassportKitTesting", package: "PassportKit"),
])
```

## A first test

```swift
import PassportKit
import PassportKitTesting

func signIn() async throws -> (OAuthClient, FakeAuthorizationServer, TokenResponse) {
    let server = FakeAuthorizationServer(clients: [
        .init(id: "app", rotatesRefreshTokens: true)
    ])
    let client = try await server.makeClient(clientID: "app")
    let request = AuthorizationRequest(
        redirectURI: URL(string: "https://app.example.com/callback")!, scope: ["read"])
    let tokens = try await client.authorize(request, using: server.userAgent())
    return (client, server, tokens)
}
```

`makeClient(clientID:wallClock:clock:)` builds a client for a registered
client that talks to the server, with the server's endpoints and issuer.
`userAgent(subject:decision:)` returns an ``AuthorizationUserAgent`` that plays
the person: it approves, or with `.deny` declines, every authorization request.
`authorizeInteractively(_:)` is the same step for a URL you hold.

## Controlling the scenario

`configure(_:)` changes the server's behaviour:

- Clients can be public or confidential, with refresh token rotation, a
  reuse leeway and a lifetime for each token type.
- `scopePolicy` narrows grants. `refreshWithUnauthorizedResource` and
  `exchangeForUnauthorizedResource` reproduce the two ways servers refuse a
  resource, so you can test your handling of both (see <doc:ResourceAccessAndScopes>).
- `override` replaces the answer to a request, with a status, body, headers,
  delay or a transport failure.
- `responseDelay` holds back an answer after the server handled the request,
  like a slow network.
- Device authorizations can be approved or denied with `approve(userCode:)`
  and `deny(userCode:)`, and `requireSlowDown(times:)` answers `slow_down`.
- `expire(token:)` makes one issued token expired.
- `requests` lists what the server received, with decoded form parameters.

## Time without sleeping

`ManualClock` implements `Clock`. Pass it as the client's `clock`, and
polling intervals, time limits and delays wait until your test advances it.
`advanceToNextSleeper()` waits for a sleeper and moves time to its deadline.
`ManualWallClock` is the calendar clock whose date you set, which decides when
tokens expire. `SequenceRandomSource` makes `state` and PKCE values
deterministic.

## Recording requests

`RecordingTransport` answers from a script and records requests. Use it to
assert on what your code sends without any server logic.

## What to test in your app

- That a denied resource hides one feature and keeps the session.
- That a rejected refresh token shows the sign-in screen.
- That your acceptance policy rejects a token with a narrowed scope.

Do not test the protocol itself: PassportKit's own conformance tests run the
same fake server.
