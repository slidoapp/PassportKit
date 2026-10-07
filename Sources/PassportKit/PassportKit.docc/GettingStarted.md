# Getting started

Configure a client, sign a person in, keep the session, and call an API.

## Configure a client

A client needs the server's endpoints and a way to authenticate. If the
server publishes metadata (RFC 8414), discover it once and let the
configuration follow what the server advertises, including whether it adds
`iss` to authorization responses (RFC 9207):

```swift
import PassportKit

let issuer = URL(string: "https://as.example.com")!
let metadata = try await Discovery.fetchMetadata(issuer: issuer)
let configuration = try ClientConfiguration(
    metadata: metadata, authentication: .none(clientID: "my-app"))
let client = try OAuthClient(configuration: configuration)
```

Use `.none` for a public client such as a native app, which cannot keep a
secret. A confidential client uses ``ClientAuthentication/clientSecretBasic(clientID:secret:)``
or ``ClientAuthentication/clientSecretPost(clientID:secret:)``. Without
discovery, build an ``Endpoints`` value by hand.

``OAuthClient/init(configuration:transport:wallClock:clock:random:observer:)``
throws ``PassportError`` with the code
``PassportError/Code-swift.struct/invalidConfiguration`` when an endpoint is
not `https` (or loopback `http`), so a misconfigured client never exists.

## Sign in with the device flow

The device authorization grant (RFC 8628) suits devices and tools without a
browser. Show the person where to go, then wait for approval:

```swift
let authorization = try await client.startDeviceAuthorization(scope: ["openid", "offline_access"])
print("Open \(authorization.verificationURI) and enter \(authorization.userCode)")
let tokens = try await client.completeDeviceAuthorization(authorization)
```

``OAuthClient/completeDeviceAuthorization(_:additionalParameters:)`` polls at
the server's interval, honours `slow_down`, backs off on server errors, stops
at the deadline and stops immediately when its task is cancelled.

## Sign in with the authorization code flow

Interactive apps use the authorization code grant with PKCE. A
``UserAgent`` shows the authorization page and returns the redirect. On
Apple platforms `PassportKitApple` provides agents; see
<doc:NativeAppRedirects>.

```swift
func signIn(using userAgent: any UserAgent) async throws -> TokenResponse {
    let request = AuthorizationRequest(
        redirectURI: URL(string: "com.example.app:/callback")!,
        scope: ["openid", "offline_access"])
    return try await client.authorize(request, using: userAgent)
}
```

The library generates `state` and the PKCE verifier, validates the redirect
and the `iss` parameter, and exchanges the code.
``OAuthClient/beginAuthorization(_:)`` and
``OAuthClient/completeAuthorization(_:callbackURL:additionalParameters:)``
split the flow when you present the URL yourself.

## Keep the session

A ``TokenResponse`` is a one-time result. Hand it to a ``TokenManager``,
which saves the refresh token to a ``CredentialStore`` and refreshes access
tokens when they run low:

```swift
let account = CredentialAccount(service: "com.example.app", account: "default")
let manager = TokenManager(client: client, store: InMemoryCredentialStore(), account: account)
try await manager.signIn(with: tokens, requestedScope: ["openid", "offline_access"])

let token = try await manager.accessToken()
```

Use ``InMemoryCredentialStore`` in tests only. On Apple platforms store the
credential in the Keychain with `PassportKitApple`'s
`KeychainCredentialStore`. On the next launch call
``TokenManager/load()`` instead of signing in again. Subscribe to
``TokenManager/events`` to learn when the session ends.

## Call an API

``RequestAuthorizer`` adds the bearer token, refreshes once when the server
rejects it, and never sends a request without a token:

```swift
let authorizer = RequestAuthorizer(manager: manager)
let session = URLSession(configuration: .ephemeral)
let request = URLRequest(url: URL(string: "https://api.example.com/items")!)
let (data, response) = try await authorizer.data(for: request, session: session)
```

Tokens are only sent over `https` or to a loopback host, and only when the
token type is `Bearer`. A 403 is delivered to you unchanged: a new token
would not carry more scope. Read <doc:ResourceAccessAndScopes> before you
rely on a token for a particular resource.

## Next steps

- <doc:SessionsAndTokenTargets> explains tokens for several APIs.
- <doc:ErrorHandling> explains what to do with each failure.
- <doc:Testing> shows how to test all of this offline.
