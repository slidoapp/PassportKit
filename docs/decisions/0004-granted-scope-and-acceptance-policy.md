# 0004. Granted scope and the token acceptance policy

- Status: accepted
- Date: 2026-10-07

## Context

RFC 6749 §3.3 lets an authorization server issue fewer scopes than
requested and still answer 200. Servers seen in practice do this when a
refresh or exchange asks for a resource the user cannot access, while a
different grant for the same resource answers `access_denied`. A client
that treats a 200 as proof of access stores a useless token and fails
later at the resource server, often in a retry loop. The library cannot
know which scopes a resource needs: that is application knowledge, and
requested scopes may be meta-scopes the server never echoes.

## Decision

- Every token records its granted scope (`scope` from the response, or
  the requested scope when omitted, RFC 6749 §5.1).
- `TokenManager` runs a `TokenAcceptancePolicy` on every issued access
  token before caching or returning it. The default accepts everything;
  `RequireAnyScope` covers the common case.
- A rejected token is discarded, a rotated refresh token from the same
  response is still persisted, the call fails with `.tokenRejected` /
  `.resourceDenied`, and the session stays signed in.
- Narrower-than-requested scope is never an error on its own.

## Consequences

Applications state their resource rules once, as a policy, and get the
same typed failure whether the server denied explicitly or answered 200
with too little.
