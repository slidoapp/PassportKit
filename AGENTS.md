# PassportKit agent instructions

PassportKit is a public, vendor-neutral OAuth 2.0 client library for Swift 6 (macOS 14 and iOS 17 only, ADR 0011).
It must work against any standards-compliant authorization server (AS). `CLAUDE.md` is a symlink to this file; edit
this file only.

## Hard rules

- **Vendor-neutral.** No company or product names, hostnames, client IDs, scopes or product logic of a specific AS in
  `Sources/`, `Tests/`, `Tools/`, fixtures or docs. Use `as.example.com` and `api.example.com`. A vendor-specific need
  is met by an RFC feature or a documented extension point, never by a special case.
- **Traceable.** Every protocol behaviour traces to an RFC section or an ADR. Update `docs/rfc-matrix.md` in the same
  change as the code and its test.
- **No secret leakage.** Never log, print, interpolate, or put into errors, `description` or `debugDescription`: access,
  refresh and ID tokens, client secrets, authorization codes, PKCE verifiers, device codes. Tests assert this
  (`RedactionCanaryTests`).
- **HTTP 200 is not proof of access.** Expose the granted `scope` of every token response (RFC 6749 §3.3, §5.1) and
  run the acceptance policy before a token becomes current.
- **Errors come from the body.** Classify token-endpoint errors by the `error` member of the JSON body (RFC 6749 §5.2),
  not by HTTP status alone.
- **Bounded retries.** Retry a protected request at most once after a 401. Never refresh on 403 or
  `insufficient_scope` (RFC 6750 §3.1). Never send a protected request without a token.
- **Resource-level failures never end the session.** Only an invalid refresh token (`invalid_grant`) does.
- **Public API is a contract.** Public API changes need a `CHANGELOG.md` entry; a new extension point needs an ADR.
- **Inject time, randomness and transport.** Core code never calls `Date()`, `Task.sleep`, `URLSession.shared` or
  random APIs directly (`scripts/check-determinism.sh` enforces it).
- **Never** push to `main`, force-push a shared branch, create a tag or publish a release unless a maintainer
  explicitly asks.

## Commands

Run from the repository root. All are non-interactive; only `make integration` needs network (first run).

```sh
make setup        # once per clone: installs the git hooks (commit-msg)
make format       # format Sources, Tests, Package.swift in place
make lint         # format check + scripts/check-determinism.sh
make build        # build with tests; warnings are errors
make test         # all offline tests, in parallel
make check        # lint + build + test: the gate for every change
make docs         # DocC archives of both libraries; fails on any warning (needs Xcode)
make test-ios     # offline suites on an iPhone simulator (needs Xcode)
make integration  # real flows against Tools/integration-server (needs Node.js)
swift test --filter <Suite>/<test>   # one test
```

## Definition of done

1. `make check` passes; quote its final line.
2. New behaviour has a test. New protocol behaviour has a row in `docs/rfc-matrix.md`.
3. Public symbols have DocC comments that cite the RFC section. If you changed public API or a DocC article,
   `make docs` passes and every code sample in an article is compiled in
   `Tests/ConformanceTests/DocumentationSnippets.swift` (or `Tests/PassportKitTests/UserAgents/UserAgentDocumentationSnippets.swift`).
4. `docs/spec.md` states the new behaviour; `docs/architecture.md` and `docs/security-model.md` change only if an
   invariant or a threat changed.
5. A user-visible change has an entry under `[Unreleased]` in `CHANGELOG.md`, marked **Breaking** when it is.

## Where things are

| Question | Read |
|---|---|
| What exactly does the API do? | `docs/spec.md` (numbered sections; code comments cite them) |
| Which module owns what, which invariants hold? | `docs/architecture.md` |
| Why was it designed this way? Was it rejected? | `docs/decisions/README.md` (ADR index) |
| Which RFC requirement is implemented where and tested by what? | `docs/rfc-matrix.md` |
| What must never leak, which threats are covered? | `docs/security-model.md` |
| How do tests work, what is the fake server? | `docs/testing.md` |
| What is open or deliberately left out? | `docs/roadmap.md` |
| How do app developers use it? | `README.md`, DocC articles in `Sources/PassportKit/PassportKit.docc` |
| What changed between releases? | `CHANGELOG.md` |
| Human contribution and release process | `CONTRIBUTING.md` |
| Security policy | `SECURITY.md` |

Source layout (`Sources/PassportKit/<Folder>`) is described in `docs/architecture.md`. Other places:
`Tools/integration-server` (the Node.js server behind `make integration`), `scripts/` (`check-determinism.sh`,
`build-docs.sh`, `test-ios.sh`), `.agents/skills` (`.claude/skills` links to it) and `.claude/agents` (reviewers).
Skills: `implement-rfc-feature`, `add-conformance-scenario`, `prepare-release` (maintainer request only). Run the
`rfc-reviewer` agent after changing protocol behaviour and `security-reviewer` after touching tokens, storage,
logging, redirects or errors.

## Keeping docs true

- One source of truth per topic; link instead of repeating. `docs/spec.md` owns behaviour, ADRs own history.
- Write docs as the present state: no "planned", "milestone", "formerly" or "now". Release history belongs in
  `CHANGELOG.md`; superseded decisions stay in their ADR with an updated Status line, never rewritten.
- Sentence case headings. Terms: token target, session, acceptance policy, refresh lane, authorization server.
- Names in prose must exist in `Sources/`; rename them in the docs in the same change as the code.

## Code style

- Swift 6 language mode with complete concurrency checking. `swift format` decides formatting; do not hand-format.
- No `@unchecked Sendable` or `nonisolated(unsafe)` without a comment explaining why it is safe. Guard state shared by a
  class with `OSAllocatedUnfairLock`.
- macOS and iOS only: no Linux paths, no tvOS, watchOS or visionOS branches. Guard only real macOS/iOS differences
  (AppKit versus UIKit) with `#if os(macOS)`.
- Typed errors that preserve the RFC error code and description.
- Prefer `async`/`await` and structured concurrency over callbacks and unstructured `Task {}`. Every long-running
  operation honours cancellation.
- Avoid acronyms in names except standard ones (`URL`, `HTTP`, `JSON`, `PKCE`, `JWT`).

## Testing

- Swift Testing (`import Testing`); parameterise over RFC example vectors where they exist.
- A new flow or edge case gets a scenario against the fake authorization server (`docs/testing.md`).
- No network, no sleeps: use the injected clocks. `ManualClock` waits throw `ManualClock.WaitTimeout`; call them with
  `try await`.
- Fixtures are evidence. Do not edit an existing fixture to make a test pass; add a new one and explain why.

## Git and pull requests

- Branch: `<github-nick>/<short-slug>`.
- Commit subject: `<type>(<scope>): <summary>`, imperative, at most 72 characters. Types: `feat`, `fix`, `refactor`,
  `test`, `docs`, `chore`, `build`, `ci`. Scope is the module name; omit it for repository-level files.
- Commit body explains why, wrapped at 72 columns. Sign commits (`git commit -S`). One intent per commit; keep
  behaviour changes separate from refactoring. The `commit-msg` hook enforces the format.
- No internal tracker IDs or links in commits, PRs or code: this repository is public.
- Open pull requests as drafts and fill in the template.
- Security policy: `SECURITY.md`.
