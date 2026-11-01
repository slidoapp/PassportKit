# 0014. Sign-out returns once local state is cleared, with a handle for the rest

- Status: accepted
- Date: 2026-11-01

## Context

`TokenManager.signOut(revoke:)` clears the session, queues the delete of the stored credential, reserves the
revocation of the refresh token (RFC 7009 §2) on the ended session's lane, and then waits for the delete and for the
revocation, up to five seconds. Its caller learns nothing until both finished.

An app often needs the moment the session is gone, not the server's answer: a sign-in that replaces the session, or a
screen that should show the signed-out state at once. The only way to learn that moment was to start `signOut` in a
task and wait for `SessionEvent.signedOut(.userInitiated)`, which the manager emits before its first suspension. That
works only while sign-outs never overlap, because two of them could each take the other's event, and it depends on an
implementation detail that the API does not promise.

The ordering guarantees of sign-out (spec §9, invariants 3 and 6; ADR 0007) all hold at the point before the first
suspension: the generation is bumped and the caches are dropped, `.signedOut` is emitted, the revocation takes its
lane turn behind requests that already send the old refresh token, and the delete is queued in the store's FIFO ahead
of any save a later sign-in makes.

## Decision

- `TokenManager.beginSignOut(revoke:)` is a synchronous actor method that does exactly the part of sign-out before the
  first suspension and returns a `PendingSignOut`. Because it does not suspend, every guarantee above holds when it
  returns, and the caller knows the session is gone.
- `PendingSignOut` is a `Sendable` value with one asynchronous property, `result: SignOutResult { get async }`,
  shaped like `Task.value`. It waits for the queued delete and for the revocation. It is a value of its own rather than
  a `Task<SignOutResult, Never>`: a task's `value` cannot report that its waiter was cancelled, and
  `RevocationOutcome.cancelled` must stay per reader.
- The revocation's time limit (`OAuthClient.revocationTimeLimit`) and its log line run in a task the manager owns,
  started by `beginSignOut`. The limit counts from when the delete finished, as before, whether or not anyone reads
  `result`, and every reader gets the same outcome. A reader whose task is cancelled gets `.cancelled`; others do not.
- `signOut(revoke:)` is `beginSignOut(revoke:)` followed by `await result`, so the two cannot drift apart.

## Consequences

Apps can carry on the moment local state is cleared and await the server later or never, without listening for
events and without a rule against overlapping sign-outs. The cost is one more public type and method. The log line of
a revocation is written even when every caller stopped waiting, which a cancelled `signOut` did not do before.
