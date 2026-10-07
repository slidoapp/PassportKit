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
3. Move `Unreleased` entries under the new version heading with today's
   date and leave an empty `Unreleased` section.
4. Run `make check`.
5. Commit as `chore: prepare release <version>` on a new branch and open a
   draft pull request.
6. Stop. Never create tags or GitHub releases; a maintainer does that.
