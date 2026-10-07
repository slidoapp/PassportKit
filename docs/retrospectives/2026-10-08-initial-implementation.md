# Retrospective: initial implementation (2026-10-07/08)

PassportKit 0.x was built in one overnight session by a coding-agent
orchestrator (Claude Opus) delegating milestones to implementation agents
(Claude Sonnet), with read-only review agents between milestones.

## Outcome

- 9 milestones from `docs/plan.md` implemented; 400 offline tests
  (unit, fake-server conformance, Apple adapters) and 16 integration tests
  against an independent, certified authorization server
  (`Tools/integration-server`, panva/oidc-provider).
- About 7,400 lines of library code and 7,800 lines of tests.
- 8 ADRs, every protocol behaviour traced in `docs/rfc-matrix.md`.
- Not verified locally: the Linux build (no container runtime or Linux
  SDK was available unattended). CI runs it.

## What worked

1. **Spec first.** `docs/spec.md`, the plan and the first ADRs were
   written before any code. Agents shared one contract and reported where
   it was wrong instead of silently diverging (ADR 0006 came from an
   agent that found a spec type unusable with injected clocks).
2. **Independent adversarial review per milestone.** Read-only reviewers
   pinned to a commit found defects the implementers' own tests missed:
   a crash on a hostile `interval`, three confirmed races in the session
   actor, credential leaks in error text, and a refresh that lost the
   granted scope. The implementer's tests share the implementer's blind
   spots; an independent reviewer does not.
3. **Red-first tests and mutation checks.** For each race fix the agent
   wrote a deterministic failing test, fixed it, then reverted the fix to
   confirm the test fails. This is the strongest evidence a concurrency
   test is real.
4. **Deterministic seams.** Injected clocks, randomness and transport
   made every flow testable without sleeping or network access; the
   conformance suite ran repeatedly without a flaky failure.
5. **A canary test for redaction.** Running every flow with unique
   secrets and searching every rendering found two real leaks on its
   first run.
6. **A real server for "real scenarios".** The integration suite passed
   against an independent implementation without finding library bugs,
   which validated the fake server model.
7. **Parallel agents in git worktrees** for independent modules; the only
   merge conflicts were append-only table rows.

## What to do differently

1. **Review the public API before implementing.** A late API review
   (journey snippets for the five main use cases) caused a large rename
   and restructuring pass: closed enums that must stay open for SemVer,
   `.none` cases colliding with `Optional.none`, verbose construction of
   common values. Do this review on the spec's API sketch first.
2. **Verify the cross-platform toolchain at setup time**, while a human
   can answer prompts and dialogs.
3. **Check free disk space before heavy work** and keep container
   runtimes off unless needed; a full disk stops the agent's own tools.
4. **Instruct agents to stage explicit paths**, never `git add -A`, when
   several agents share a checkout.
5. **Use the stronger model for factual research.** A cheaper model gave
   confidently wrong capability claims about third-party servers.
6. **Ask for chunked output.** Very large single responses were the
   main cause of agent failures early on.

## Open items

See `docs/plan.md` → Next, `docs/security-model.md` → Known limits, and
`partial` rows in `docs/rfc-matrix.md`.
