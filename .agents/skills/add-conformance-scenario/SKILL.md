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
3. **Add a fixture** under `Tests/Fixtures/` if the exchange is reused.
   Never modify an existing fixture to make a test pass.
4. **Script the fake server** in `Tests/ConformanceTests`: scripted
   responses for each request, and assertions on the requests the client
   sent (parameters, headers, ordering).
5. **Assert the client outcome:** returned token or typed error, granted
   scope, what was persisted, and that the session was or was not ended.
6. Run `make check`.
