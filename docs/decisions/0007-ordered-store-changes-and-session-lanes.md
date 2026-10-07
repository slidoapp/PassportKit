# 0007. Ordered store changes, a lane per session, revocation of the newest token

- Status: accepted
- Date: 2026-10-08

## Context

ADR 0005 made every refresh-token operation run in one lane and discard
results of ended sessions. An adversarial review of `TokenManager` found
interleavings that this left open, all caused by work that suspends:

- A store may take long for a save and a delete, and the manager awaited
  both concurrently. A save issued by a refresh could take effect after
  the delete of a later sign-out and bring the session back on the next
  `load()`.
- `signOut(revoke:)` revokes the refresh token it read before suspending.
  A request already sending that token rotates it at the server, and the
  manager discards the response as stale, so the live token is never
  revoked (RFC 7009 §2.1 revokes the token, and the grant only at the
  server's discretion).
- One lane for the manager meant a request of an ended session that never
  answers held up the next session. A time limit built on a task group
  does not help, because a group cannot return before children that
  ignore cancellation.
- `signIn` set the credential, then awaited the store and the policy
  before caching its token. A caller in that window refreshed with the
  grant's first refresh token and was then overwritten by the older token.
- A rejected token was never cached, so a retry loop rotated the refresh
  token on every attempt, and a hung policy held the lane for ever.

## Decision

- **One FIFO for store changes.** Every save and delete goes through
  `changeStore`, which chains each change behind the previous one. The
  order is the order in which the manager decides them, so the store
  ends in the state the manager last chose. Each change runs in a task
  of its own, so cancelling a caller neither skips nor interrupts it.
- **One lane per session.** Starting a new session gives the manager a
  fresh lane; turns of the old one finish on it. A sign-out revokes on
  the lane of the session it ended, so the revocation still queues
  behind that session's in-flight requests.
- **Revocation reads the newest token at its turn.** A sign-out that
  revokes records the token in `revocableTokens[endedSession]`. A request
  of that session that completes after the sign-out hands over the
  refresh token it was issued before its result is discarded. The
  revocation removes the entry when its turn starts and sends what is
  there.
- **`signIn` registers a flight for the default token before it
  suspends**, so callers in the window join it instead of refreshing.
  Callers whose session was replaced while they waited resolve once more
  against the current session.
- **Rejections are bounded and remembered.** The policy runs under a time
  limit (`acceptancePolicyTimeLimit`, default 10 s); no answer is a
  rejection. A rejection is remembered per target for
  `rejectedTokenCacheDuration` (default 30 s) and thrown without a
  request. `withTimeLimit` races the operation in an unstructured task
  and returns when either finishes.

## Consequences

A hung store still blocks later store changes and therefore a sign-out
that waits for its delete; before this change it blocked the delete only,
and the lane too whenever the hung call was a save from a refresh. A
non-cooperative operation that outlives its time limit keeps running in
the background until it ends. Two sessions can talk to the server
concurrently, each on its own token chain. The cost of the negative
cache is that a resource that becomes accessible within 30 s is not
retried until `invalidate(_:)`, a sign-in or the window passes.
