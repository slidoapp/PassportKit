# 0003. One error type, classified by the OAuth error code

- Status: accepted
- Date: 2026-10-07

## Context

Authorization servers return OAuth errors with varying HTTP statuses;
some return `access_denied` with 401. Clients that map statuses to
errors before reading the body misreport resource denials as expired
sessions and either sign users out or retry in loops.

## Decision

All library failures are `PassportError`, a struct with an open `Code`
(server codes are preserved) and a `Recovery` that tells the caller
whether the session is gone (`reauthenticate`), only a resource is
denied (`resourceDenied`), the call may be retried, or configuration is
wrong. The JSON `error` member decides the code; the HTTP status is only
recorded.

Public functions use untyped `throws`. They throw `PassportError` or
`CancellationError`; cancellation is never wrapped.

## Consequences

Callers switch on `recovery` for control flow and on `code` for detail.
Typed throws can be adopted later without changing the error type.
