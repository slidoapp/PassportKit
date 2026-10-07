# How to Contribute

Thanks for your interest in contributing to PassportKit! Here are a few
general guidelines on contributing and reporting bugs that we ask you to
review. Following these guidelines helps to communicate that you respect the
time of the contributors managing and developing this open source project. In
return, they should reciprocate that respect in addressing your issue,
assessing changes, and helping you finalize your pull requests. In that spirit
of mutual respect, we endeavor to review incoming issues and pull requests
within 10 days, and will close any lingering issues or pull requests after 60
days of inactivity.

Please note that all of your interactions in the project are subject to our
[Code of Conduct](/CODE_OF_CONDUCT.md). This includes creation of issues or
pull requests, commenting on issues or pull requests, and extends to all
interactions in any real-time space e.g., Slack, Discord, etc.

## Reporting Issues

Before reporting a new issue, please ensure that the issue was not already
reported or fixed by searching through our
[issues list](https://github.com/slidoapp/PassportKit/issues).

When creating a new issue, please be sure to include a **title and clear
description**, as much relevant information as possible, and, if possible, a
test case. For bugs, include a redacted HTTP exchange (no real tokens, codes,
or secrets).

For new features, open an issue first. PassportKit implements standards: a
proposal should name the RFC section it implements, or explain why a generic
extension point is needed.

**If you discover a security bug, please do not report it through GitHub.
Instead, please see security procedures in [SECURITY.md](/SECURITY.md).**

## Sending Pull Requests

Before sending a new pull request, take a look at existing pull requests and
issues to see if the proposed change or fix has been discussed in the past, or
if the change was already implemented but not yet released.

We expect new pull requests to include tests for any affected behavior, and,
as we follow semantic versioning, we may reserve breaking changes until the
next major version release.

### Development

Requirements: Swift 6.2 or later (Xcode 26 or later on macOS).

```sh
make setup   # installs the git hooks
make check   # lint + build + test; must pass before a pull request
```

Use `make format` to format code. Run a single test with
`swift test --filter <Suite>/<test>`. `make lint` also runs
`scripts/check-determinism.sh`, which keeps `Date()`, `Task.sleep`,
`URLSession.shared` and random APIs out of the core: inject a seam instead.

Two more targets are not part of `make check`:

```sh
make integration   # real flows against a local authorization server
make docs          # builds the DocC archives; fails on any warning
```

`make integration` needs [Node.js](https://nodejs.org) (24 is what CI uses):
it starts the server in `Tools/integration-server`, and the first run
installs it with `npm ci`, which needs network access. The tests are skipped
unless the server is running, so `make check` stays offline. `make docs`
needs Xcode. Changing a public symbol or an article? Run it, and keep the
article's code samples in sync with
`Tests/ConformanceTests/DocumentationSnippets.swift`.

Design background lives in [docs/](docs/): start with
[architecture.md](docs/architecture.md) and the decision records in
[docs/decisions/](docs/decisions/).

### Commits and pull requests

- Commit subject: `<type>(<scope>): <summary>` in the imperative mood,
  at most 72 characters. Types: `feat`, `fix`, `refactor`, `test`,
  `docs`, `chore`.
- The commit body explains why the change is needed, wrapped at 72
  columns.
- One intent per commit. Keep behaviour changes separate from
  refactoring.
- Add a `CHANGELOG.md` entry under `Unreleased` for user-visible changes.
- Pull requests need passing CI and a review from a code owner.

### AI coding agents

Agent instructions live in [AGENTS.md](AGENTS.md). Contributions made
with coding agents follow the same rules as any other contribution, and
the human author is responsible for them.

## Other Ways to Contribute

We welcome anyone that wants to contribute to PassportKit to triage and reply
to open issues to help troubleshoot and fix existing bugs. Here is what you
can do:

- Help ensure that existing issues follows the recommendations from the
  _[Reporting Issues](#reporting-issues)_ section, providing feedback to the
  issue's author on what might be missing.
- Review and update the documentation in [docs/](docs/) and the DocC
  articles with up-to-date instructions and code samples.
- Review existing pull requests, and testing patches against real existing
  applications that use PassportKit.
- Write a test, or add a missing test case to an existing test.

Thanks again for your interest on contributing to PassportKit!

:heart:
