---
name: prepare-release
description: Prepare a PassportKit release pull request. Only when a maintainer explicitly asks to prepare a release.
disable-model-invocation: true
---

# Prepare a release

1. Read `CHANGELOG.md` `Unreleased` and the commits since the last tag
   (`git log $(git describe --tags --abbrev=0)..HEAD`).
2. Determine the next version with Semantic Versioning. Before 1.0, a
   breaking change bumps the minor version; from 1.0, it bumps the major
   version. Run
   `swift package diagnose-api-breaking-changes <last-tag>` to confirm.
3. Rename `[Unreleased]` to `## [<version>] - <today>`, add a fresh empty
   `[Unreleased]` section above it, and update the link references at the
   end of `CHANGELOG.md` (`[Unreleased]` compares the new tag with `HEAD`).
   The section text becomes the release notes, so it must stand alone.
4. Check that the installation snippet in `README.md` names the new
   minor version, then run `make check` and
   `make docs`.
5. Commit as `chore: prepare release <version>` on a new branch and open a
   draft pull request.
6. Stop. Never create tags or GitHub releases; a maintainer does that.
