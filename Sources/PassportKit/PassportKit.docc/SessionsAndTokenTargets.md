# Sessions and token targets

One ``TokenManager`` holds one signed-in root grant and every access token
derived from it.

## The root grant

``TokenManager/signIn(with:requestedScope:)`` adopts the result of a sign-in
flow. The refresh token and ID token become the stored ``Credential``; the
access token of the response is cached as the first token of the
``TokenTarget/default`` target. Only the credential is persisted. Access
tokens live in memory and are asked for again after a restart.

A grant that issued no refresh token still works until its access token
expires. Then the session ends with the reason
``SignOutReason/expiredWithoutRefreshToken``.

## Asking for a token

``TokenManager/accessToken(for:)`` returns a token that is valid for at least
the configured minimum lifetime, refreshing when needed. A ``TokenTarget``
says what the token is for:

```swift
let items = URL(string: "https://api.example.com/items")!

// The default: the root grant's own token.
let general = try await manager.accessToken()

// A token bound to one resource (RFC 8707), refreshed from the root grant.
let bound = try await manager.accessToken(
    for: TokenTarget(resources: [items], scope: ["items.read"]))

// A token for another service, exchanged from the default token (RFC 8693).
let exchanged = try await manager.accessToken(
    for: TokenTarget(method: .exchangeAccessToken, audiences: ["reports"]))
```

Two targets are equal when their method, scope and the sets of resources and
audiences are equal. Order and repetition do not matter. A token is never
handed to a caller that asked for a different target, so a token for one API
is not reused for another. Concurrent callers for the same target share one
request.

## Refresh or exchange

- ``TokenTarget/Method/refreshGrant`` sends a refresh grant that names the
  resources and scope. It narrows what the root grant allows.
- ``TokenTarget/Method/exchangeAccessToken`` exchanges the default access
  token for one bound to resources or audiences. The server decides whether
  the exchange is allowed. A derived token never outlives the token it came
  from.

A target with audiences must use the exchange method. Use the refresh grant
when the server issues resource-bound tokens from the refresh token, and the
exchange when your server requires it.

``TokenManager/exchangeRefreshToken(audience:resources:scope:requestedTokenType:)``
exchanges the refresh token itself, for example to hand a refresh token to
another component. It is not cached and does not run the acceptance policy;
the result belongs to your app.

## Rotation and the lane

Servers may rotate the refresh token on every use and allow little or no
reuse. Every operation that sends the refresh token (refresh,
refresh-token exchange, revocation) therefore runs in one first-in
first-out lane per session. The lane reads the refresh token when its turn
starts, so it always sends the newest one, and a rotated token is saved to
the store before the access token is returned. If saving fails the session
continues in memory and ``SessionEvent/storageFailed`` is emitted.

You do not manage the lane. The consequences for you:

- Calls never overlap on the wire when they spend the refresh token, so a
  burst of requests cannot burn a rotating token.
- Cancelling a caller only stops it waiting. A request that was sent
  finishes and its rotated token is saved.
- Results that arrive after a sign-out or a new sign-in are discarded.
  Each session has its own lane, so a request that never answers cannot
  block the next session.

## When a session ends

Only the server rejecting the refresh token (`invalid_grant`) ends a
session: the credential is deleted, ``SessionEvent/signedOut(reason:)`` is
emitted, and later calls throw ``PassportError/Code-swift.struct/notAuthenticated``
with recovery ``PassportError/Recovery-swift.enum/reauthenticate``. Failures
that concern one resource never end it; see <doc:ResourceAccessAndScopes>.

``TokenManager/signOut(revoke:)`` clears the session and, by default,
revokes the newest refresh token (RFC 7009) with a time limit. The
``SignOutResult`` reports whether the stored credential was deleted and what
happened to the revocation; the in-memory session is always cleared.

## After a 401

``TokenManager/invalidate(_:)`` drops a cached token that a resource server
rejected. Pass the exact ``AccessToken`` that was used: only that token is
dropped, so many concurrent 401s for one token cause one refresh.
``RequestAuthorizer`` does this for you.
