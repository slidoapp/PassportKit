# PassportKit — Agent Instructions

PassportKit is a generic, open-source OAuth 2.0 client library for Swift.
It is public and vendor-neutral: it must work against any standards-compliant
authorization server (AS).

`CLAUDE.md` is a symlink to this file. Edit this file only.

## Non-negotiables

- **Vendor-neutral.** No company or product names, hostnames, client IDs,
  scopes, or product logic of any specific AS in `Sources/`, `Tests/`,
  fixtures, or docs. Use `as.example.com` / `api.example.com`. A
  vendor-specific need is met by an RFC feature or a documented extension
  point, never by a special case.
- **Traceable.** Every protocol behaviour traces to an RFC section or an
  ADR in `docs/decisions/`. Update `docs/rfc-matrix.md` in the same change
  as the code and its test.
- **No secret leakage.** Never log, print, interpolate, or put into errors,
  `description`, or `debugDescription`: access/refresh/ID tokens, client
  secrets, authorization codes, PKCE verifiers, device codes. Tests assert
  this.
- **HTTP 200 is not proof of access.** Expose the granted `scope` of every
  token response (RFC 6749 §3.3, §5.1) and run the app-supplied token
  acceptance hook before a token becomes current. An AS may narrow scope
  and still answer 200.
- **Errors come from the body.** Classify token-endpoint errors by the
  `error` code in the JSON body (RFC 6749 §5.2), not by HTTP status alone.
- **Bounded retries.** Retry a protected request at most once after a 401.
  Never refresh on 403 or `insufficient_scope` (RFC 6750 §3.1). Never send
  a protected request without a token.
- **Resource-level failures never end the session.** Only an invalid
  refresh token (`invalid_grant`) ends a session.
- **Public API is a contract.** Public API changes need a CHANGELOG entry,
  and new extension points need an ADR.

## Commands

Run from the repository root. Every command is non-interactive and offline.

```sh
make setup     # once per clone: installs git hooks
make format    # format Sources, Tests, Package.swift in place
make lint      # formatting check and scripts/check-determinism.sh, fails on any finding
make build     # build including tests; warnings are errors
make test      # run all tests in parallel
make check     # lint + build + test — the definition of done
make docs      # DocC archives of all libraries; fails on any warning (needs Xcode)
make integration  # real flows against Tools/integration-server (needs Node.js)
swift test --filter <Suite>/<test>   # a single test
```

## Definition of done

1. `make check` passes; quote its final summary line.
2. New behaviour has a test; new protocol behaviour has a row in
   `docs/rfc-matrix.md`.
3. Public symbols have DocC comments referencing the RFC section. After
   changing public API or an article, `make docs` passes (no warnings) and
   the article samples in `Tests/ConformanceTests/DocumentationSnippets.swift`
   still match.
4. User-visible changes have an entry under `Unreleased` in `CHANGELOG.md`.

## Where things are

- `docs/spec.md` — the implementation contract: public API and behaviour.
- `docs/plan.md` — milestones and their done criteria.
- `docs/architecture.md` — module boundaries, concurrency model,
  invariants. Read before cross-module changes.
- `docs/rfc-matrix.md` — RFC requirement → code → test traceability.
- `docs/security-model.md` — threats, redaction and storage rules.
- `docs/testing.md` — test layers, fake authorization server, fixtures.
- `Sources/*/*.docc` — DocC catalogs; the articles are in
  `Sources/PassportKit/PassportKit.docc`.
- `Tools/integration-server` — the local authorization server that
  `make integration` runs the `IntegrationTests` against (Node.js).
- `scripts/` — `check-determinism.sh` (run by `make lint`) and
  `build-docs.sh` (run by `make docs`).
- `docs/decisions/` — ADRs. Check them before proposing a design change;
  do not re-propose rejected designs without new information.

## Code style

- Swift 6 language mode with complete concurrency checking.
- No `@unchecked Sendable` or `nonisolated(unsafe)` without a comment that
  explains why it is safe.
- `swift format` decides formatting. Do not hand-format.
- Inject time, randomness, and HTTP transport. Core code never calls
  `Date()`, `URLSession.shared`, or random APIs directly.
- Core code builds on Linux: no `Security`, `AuthenticationServices`,
  `AppKit`, or `UIKit` imports outside the Apple adapter module.
- Typed errors that preserve the RFC error code and description.
- Prefer `async`/`await` and structured concurrency over callbacks and
  unstructured `Task {}`. Every long-running operation honours
  cancellation.
- Avoid acronyms in names except standard ones (`URL`, `HTTP`, `JSON`,
  `PKCE`, `JWT`).

## Testing

- Use Swift Testing (`import Testing`); parameterise over RFC example
  vectors where they exist.
- A new flow or edge case gets a scenario against the fake authorization
  server.
- No network access, no sleeps: use the injected clock.
- Fixtures are evidence. Do not edit an existing fixture to make a test
  pass; add a new one and explain why.

## Git and pull requests

- Branch: `<github-nick>/<short-slug>`.
- Commit subject: `<type>(<scope>): <summary>`, imperative, ≤ 72 chars.
  Types: `feat`, `fix`, `refactor`, `test`, `docs`, `chore`, `build`, `ci`.
  Scope is the module name; omit it for repository-level files.
- Commit body explains why, wrapped at 72 columns. Sign commits
  (`git commit -S`). One intent per commit; keep behaviour changes separate
  from refactoring.
- No internal tracker IDs or links in commits, PRs, or code: this repo is
  public.
- Open pull requests as drafts. Fill in the PR template.
- Never push to `main`, force-push shared branches, create tags, or
  publish releases unless a maintainer explicitly asks.

## Security

Vulnerabilities are reported privately (see `SECURITY.md`). Never open a
public issue or PR that discloses one.
