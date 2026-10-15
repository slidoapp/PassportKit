---
name: add-conformance-scenario
description: Model a specific authorization server behaviour (including non-standard quirks) as a conformance test against the fake authorization server. Use when reproducing a bug report or covering an edge case.
---

# Add a conformance scenario

1. **Describe the behaviour generically.** Name the scenario after what
   the server does, never after a vendor. Example: "refresh with resource
   indicator returns 200 with narrowed scope", not "Vendor X refresh".
2. **Sanitise captured traffic.** If you start from a real HTTP exchange:
   replace every token, code, and secret with obvious placeholders,
   replace hostnames with `as.example.com` / `api.example.com`, and drop
   headers that identify a vendor.
3. **Script the fake server** in `Tests/ConformanceTests`: the controls of
   `FakeAuthorizationServer` (`configure`, `override`, `responseDelay`,
   `omitsScope`, ...) or a `RecordingTransport` script, and assertions on
   the requests the client sent (parameters, headers, ordering). See
   `docs/testing.md`. If one captured exchange is reused by several tests,
   store it under `Tests/Fixtures/`; never modify an existing fixture to
   make a test pass.
4. **Use the injected clocks.** No sleeps; `ManualClock` waits throw, so
   call them with `try await`.
5. **Assert the client outcome:** returned token or typed error, granted
   scope, what was persisted, and that the session was or was not ended.
6. Add a row or a test reference to `docs/rfc-matrix.md` if the scenario
   covers an RFC requirement, then run `make check`.
