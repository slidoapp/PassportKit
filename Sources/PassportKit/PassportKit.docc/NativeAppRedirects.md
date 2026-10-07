# Native app redirects

The authorization code flow ends with a redirect back to your app. How the
redirect reaches you depends on the platform. RFC 8252 describes the
options; PassportKit's `PassportKitApple` module implements the common ones.
The core library only defines the ``UserAgent`` protocol, so you can bring
your own.

## ASWebAuthenticationSession

On iOS, macOS and visionOS use `WebAuthenticationSessionUserAgent`. It wraps
`ASWebAuthenticationSession`: the system presents a browser sheet that can
share the person's sign-in with Safari, and returns the redirect without
leaving your app.

```swift
import PassportKit
import PassportKitApple

@MainActor
func signIn(client: OAuthClient) async throws -> TokenResponse {
    let request = AuthorizationRequest(
        redirectURI: URL(string: "com.example.app:/callback")!,
        scope: ["openid", "offline_access"])
    let userAgent = WebAuthenticationSessionUserAgent(prefersEphemeralWebBrowserSession: false)
    return try await client.authorize(request, using: userAgent)
}
```

Use a private-use URI scheme that you own, written in reverse domain order,
or an `https` claimed URL where the OS supports it (macOS 14.4, iOS 17.4,
visionOS 1.1). Register the redirect URI at the server exactly as written:
the library compares it exactly. Pass
`prefersEphemeralWebBrowserSession: true` to skip shared sign-in, so the
person is always asked to authenticate. If the person dismisses the sheet you
get ``PassportError/Code-swift.struct/userCancelled``.

## Loopback redirect

Desktop apps and command-line tools can listen on `127.0.0.1` (RFC 8252
§7.3). Start the listener first, because the redirect URI carries the port the
system assigned:

```swift
import PassportKit
import PassportKitApple

func signIn(client: OAuthClient) async throws -> TokenResponse {
    let listener = try await LoopbackRedirectListener.start()
    let request = AuthorizationRequest(redirectURI: listener.redirectURI, scope: ["openid"])
    return try await client.authorize(request, using: LoopbackUserAgent(listener: listener))
}
```

The listener binds the loopback interface only, accepts the first matching
request, answers with a short page that does not echo the query, and stops.
The authorization server must accept a loopback redirect URI with any port.
`LoopbackUserAgent` opens the system browser by default; pass `openURL:` to
open the URL yourself, for example to print it.

## Device flow

When the device has no browser or no keyboard (a television, a command-line
tool over SSH), use the device authorization grant instead. Nothing has to
reach your app: the person approves on another device while your app polls.
See <doc:GettingStarted>. It needs a device authorization endpoint and a client
registered for the grant.

## Choosing

| Situation | Use |
|---|---|
| iOS, macOS or visionOS app with UI | `WebAuthenticationSessionUserAgent` |
| macOS tool or app without a registered scheme | `LoopbackUserAgent` |
| tvOS, watchOS, headless | Device flow |
| Linux | Device flow, or your own ``UserAgent`` |

Never present the authorization page in an embedded web view that your app
can read: the person's credentials would pass through your code.
