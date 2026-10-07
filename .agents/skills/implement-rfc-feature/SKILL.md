---
name: implement-rfc-feature
description: Implement or extend support for an OAuth RFC feature in PassportKit (for example "add RFC 8628 device flow" or "support RFC 9207 iss validation"). Use for any new protocol behaviour.
---

# Implement an RFC feature

1. **Read the source.** Fetch the relevant RFC sections from
   `https://www.rfc-editor.org/rfc/rfcNNNN`. Note every MUST, SHOULD, and
   MAY that applies to a client.
2. **Check decisions.** Read `docs/architecture.md` and
   `docs/decisions/`. If the feature needs a new extension point or
   changes public API shape, write an ADR first (`0000-template.md`).
3. **Record requirements.** Add one row per client requirement to
   `docs/rfc-matrix.md` with status `planned`.
4. **Write failing tests.** Unit tests for request building and response
   parsing (use RFC example vectors where they exist), and a conformance
   scenario against the fake authorization server for the end-to-end
   flow, including the error responses the RFC defines.
5. **Implement.** Core logic in the core module; platform-specific parts
   only in the Apple adapter module. Inject transport, clock, and
   randomness.
6. **Document.** DocC comments on public symbols with the RFC section.
7. **Update** `docs/rfc-matrix.md` rows to `done` with code and test
   references, and add a `CHANGELOG.md` entry under `Unreleased`.
8. **Verify.** Run `make check`. Then run the `rfc-reviewer` and, if
   tokens, storage, redirects, or logging changed, the
   `security-reviewer` subagent (Claude), or perform the same review
   checklists from `.claude/agents/` yourself (other agents).
