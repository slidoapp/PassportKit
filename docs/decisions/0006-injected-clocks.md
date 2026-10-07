# 0006. Durations on an injected clock, not instants

- Status: accepted
- Date: 2026-10-07

## Context

`OAuthClient` takes `any Clock<Duration>` so tests and apps control
sleeping and timeouts. `Clock.Instant` is an associated type: with an
existential clock it cannot be stored in a public struct. The first
sketch of `DeviceAuthorization` used `expiresAt: ContinuousClock.Instant`,
which only works with the real clock and would make the polling deadline
untestable without sleeping.

## Decision

Deadlines are tracked as `Duration` offsets measured by an internal
`Stopwatch` that opens the existential clock once and keeps the start
instant in a closure. `DeviceAuthorization` carries `expiresIn` (as
granted), `remainingLifetime` (granted lifetime minus the stopwatch,
never negative) and `expiresAt: Date` computed from the injected
`WallClock` for display only. Polling takes `remainingLifetime` when it
starts, runs its own stopwatch on the client's clock, and sleeps with
`min(wait, remaining)` so it never sleeps past, or sends after, the
deadline. Observer durations use the same stopwatch.

## Consequences

Nothing public exposes a clock instant, so any `Clock<Duration>` works,
including a manual one that never sleeps for real. A `DeviceAuthorization`
must be completed by a client whose clock advances like the one that
started it; the lifetime is not restored across app launches, which is
acceptable because the flow is interactive and short lived.
