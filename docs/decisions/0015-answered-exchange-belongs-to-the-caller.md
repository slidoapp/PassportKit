# 0015. An answered token exchange belongs to the caller

- Status: accepted
- Date: 2026-11-01
- Amends: [0007](0007-ordered-store-changes-and-session-lanes.md), for `exchangeRefreshToken`

## Context

ADR 0005 and ADR 0007 discard the result of any lane operation that finishes after its session ended or was
replaced, and hand the rotated refresh token to the ended session's revocation. For a refresh that is right: its
access token belongs to the session. `TokenManager.exchangeRefreshToken` is different. The token it obtains (RFC 8693
§2.2.1, in `access_token`) is issued for another audience, usually another client, and the manager never caches it;
it belongs to the application. Discarding the response threw that token away while it stayed valid at the server.

The manager cannot revoke it instead. RFC 7009 §2.1 lets only the client the token was issued to revoke it, and the
audience need not be a client of this manager's configuration. A vendor-neutral library cannot know who that is.

## Decision

- When the server answered an exchange, `exchangeRefreshToken` returns the response even if the session ended or was
  replaced while the request was in flight. Nothing of it reaches the current session: the rotated subject is not
  persisted and goes to the ended session's revocation, as for any superseded lane operation (ADR 0007).
- The documentation says so prominently: a caller that must not use a token of an ended session checks its own
  state when the call returns and discards the token, revoking it as the client it was issued to.
- Unchanged: a call whose session ended before its request was sent sends nothing and throws `notAuthenticated`, and
  a failure that arrives after the session ended is reported the same way, so a stale `invalid_grant` never ends a
  newer session. Refreshes keep discarding superseded results.

## Consequences

No issued token is lost silently, and the application can revoke what it cannot use. The cost is that a successful
return no longer proves that the session that made the request still exists; callers that care compare their own
state, which they already had to do for anything that arrives after a sign-out.
