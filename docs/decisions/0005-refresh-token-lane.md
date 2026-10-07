# 0005. One lane for refresh-token operations

- Status: accepted
- Date: 2026-10-07

## Context

With refresh-token rotation, every refresh and every exchange that uses
the refresh token as subject invalidates the token it sent. Servers
allow little or no reuse. Concurrent operations that read the same token
cause `invalid_grant` and sign users out; dropping the rotated token from
an exchange response does the same.

## Decision

`TokenManager` runs every operation that sends the refresh token in one
FIFO lane, reading the token when the operation starts. Concurrent
requests for the same target coalesce. Any response carrying
`refresh_token` for the root grant is persisted before results are
published. Results that complete after sign-out or a new sign-in are
discarded by a generation check. Once sent, a request is allowed to
finish even if every caller cancelled.

## Consequences

Throughput of refreshes is serialized per session, which is acceptable
because they are rare. Coordination across processes is out of scope;
apps sharing one stored credential across processes must handle it.
