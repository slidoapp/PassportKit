# Resource access and scopes

An HTTP 200 from the token endpoint does not prove that the token grants
access to what you asked for.

## What the server granted

Every token response carries the granted `scope` (RFC 6749 §3.3, §5.1). When
the response omits it, the granted scope is the requested scope, and for a
refresh that names none, the scope originally granted (RFC 6749 §6).
PassportKit records it on ``TokenResponse/scope`` and on
``AccessToken/grantedScope``, and never decides what a scope means. A server
may grant less than you asked for and still answer 200. Treating the 200 as
success lets a request fail later, at the resource, with an error far from its
cause.

## The acceptance policy

A ``TokenAcceptancePolicy`` is your hook between "the server issued a token"
and "the token becomes current". It runs on every token ``TokenManager``
issues, before the token is cached or returned. A rejected token is thrown
away, the rotated refresh token from the same response is still saved, and
the session stays signed in.

``RequireAnyScope`` covers the common case. Accept a token for a resource
only if at least one of the scopes you name was granted:

```swift
let policy = RequireAnyScope(["items.read", "items.write"])
let manager = TokenManager(
    client: client, store: InMemoryCredentialStore(), account: account, acceptancePolicy: policy)
```

By default the policy applies to targets that name resources, which is
where servers narrow scope when the person cannot use the resource. Pass
`forTargets:` with ``TargetSelector/all`` or ``TargetSelector/matching(_:)``
to choose other targets. A token whose granted scope is unknown is rejected.

``TokenManager`` accepts every token when you pass no policy, scope
narrowing included. Pass one whenever your app depends on a scope or a
resource.

For anything else, write a closure with ``TokenAcceptancePolicy/custom(_:)``
or implement the protocol. The policy has a time limit, and no answer in
time counts as a rejection.

```swift
let manager = TokenManager(
    client: client, store: InMemoryCredentialStore(), account: account,
    acceptancePolicy: .custom { context in
        context.token.grantedScope?.scopes.contains("items.read") == true
            ? .accept : .reject(reason: "The items scope is missing.")
    })
```

## Two ways a server says no

Servers differ in how they refuse access to a resource. Both happen in
practice, and both end up in the same place for the caller:

- **200 with a narrowed scope.** A refresh grant for a resource answers
  200 and a token whose scope lacks what you need. The acceptance policy
  rejects it.
- **401 `access_denied`.** A token exchange for a resource the person may
  not use answers 401 with `access_denied`.

Either way ``TokenManager/accessToken(for:)`` throws a ``PassportError``
whose recovery is ``PassportError/Recovery-swift.enum/resourceDenied``: the
rejection comes as ``PassportError/Code-swift.struct/tokenRejected`` in the
first case and as ``PassportError/Code-swift.struct/accessDenied`` in the
second. The session is intact. Handle both with one branch:

```swift
func items(using manager: TokenManager) async throws -> Data? {
    do {
        let token = try await manager.accessToken(
            for: .refreshGrant(resources: [URL(string: "https://api.example.com/items")!]))
        // Use the token.
        _ = token
        return nil
    } catch let error as PassportError where error.recovery == .resourceDenied {
        // This person cannot use this resource. Hide the feature; stay signed in.
        return nil
    }
}
```

A rejected token is remembered for 30 seconds by default
(`rejectedTokenCacheDuration`), so a view that retries in a loop does not
make the manager rotate the refresh token again and again. Set it to `.zero`
to ask the server every time.

## At the resource server

``RequestAuthorizer`` follows RFC 6750 §3.1:

- A 401 without a Bearer error code, or with `invalid_token`, drops the token,
  gets a fresh one and retries once.
- A 401 with `insufficient_scope` fails with
  ``PassportError/Code-swift.struct/insufficientScope`` and recovery
  ``PassportError/Recovery-swift.enum/resourceDenied``. A new token would
  not carry more scope.
- A 401 that only offers other schemes (`Basic`, `DPoP`) is delivered to you
  as it is: a new bearer token would not change the answer.
- A 403 is delivered to you as it is. It is never refreshed.
- A second 401 after the retry fails with
  ``PassportError/Code-swift.struct/unauthorized``, also `resourceDenied`.

Retrying once after `invalid_token` is the library's policy; RFC 6750 §3.1
does not prescribe it.

The token goes to whichever host the request names. If you build request URLs
from data you do not control (links in a response, stored addresses), pass the
origins you trust, so the token is never sent anywhere else:

```swift
let authorizer = RequestAuthorizer(
    manager: manager, allowedOrigins: [URL(string: "https://api.example.com")!])
```

A request for another origin fails with
``PassportError/Code-swift.struct/invalidConfiguration`` before a token is
obtained. A token that is not a valid `b64token` (RFC 6750 §2.1) is refused
with ``PassportError/Code-swift.struct/invalidResponse`` instead of being
written into a header. `data(for:target:session:)` never lets a redirect take
the token to another origin or from HTTPS to HTTP, whatever the session's own
delegate does.

Resource-level failures never end the session. Only an invalid refresh token
does.
