# 0001. Record architecture decisions

- Status: accepted
- Date: 2026-10-07

## Context

PassportKit is developed by humans and coding agents. Without a record of
why a design was chosen, contributors re-propose rejected designs and
cannot tell intended constraints from accidents.

## Decision

We record significant decisions as Architecture Decision Records in
`docs/decisions/`, numbered sequentially, using `0000-template.md`.
A decision is significant if it adds or changes an extension point,
changes public API shape, changes platform or toolchain support, or
deviates from an RFC recommendation.

## Consequences

Contributors check existing ADRs before proposing design changes.
Superseded ADRs stay in place and link to their replacement.
