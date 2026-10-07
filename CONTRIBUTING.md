# Contributing to PassportKit

Thanks for your interest in contributing.

## Before you start

- For bugs, open an issue with a redacted HTTP exchange (no real tokens,
  codes, or secrets).
- For new features, open an issue first. PassportKit implements
  standards: a proposal should name the RFC section it implements, or
  explain why a generic extension point is needed.
- Security issues: see [SECURITY.md](SECURITY.md). Do not open a public
  issue.

## Development

Requirements: Swift 6.2 or later (Xcode 26 or later on macOS).

```sh
make setup   # installs the git hooks
make check   # lint + build + test; must pass before a pull request
```

Use `make format` to format code. Run a single test with
`swift test --filter <Suite>/<test>`.

Design background lives in [docs/](docs/): start with
[architecture.md](docs/architecture.md) and the decision records in
[docs/decisions/](docs/decisions/).

## Commits and pull requests

- Commit subject: `<type>(<scope>): <summary>` in the imperative mood,
  at most 72 characters. Types: `feat`, `fix`, `refactor`, `test`,
  `docs`, `chore`.
- The commit body explains why the change is needed, wrapped at 72
  columns.
- One intent per commit. Keep behaviour changes separate from
  refactoring.
- Add a `CHANGELOG.md` entry under `Unreleased` for user-visible changes.
- Pull requests need passing CI and a review from a code owner.

## AI coding agents

Agent instructions live in [AGENTS.md](AGENTS.md). Contributions made
with coding agents follow the same rules as any other contribution, and
the human author is responsible for them.
