# Architecture decision records

An ADR records why a design was chosen. Read the ones that touch your change before proposing a design, and do not
re-propose a rejected design without new information. ADRs are history: never rewrite a decision. A later decision
supersedes or amends it, and both Status lines say so. The current behaviour is in [`docs/spec.md`](../spec.md).

Add a record by copying [0000-template.md](0000-template.md) when a change adds an extension point, changes the shape of
public API, adds a dependency or changes a module boundary.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-record-architecture-decisions.md) | Record decisions as ADRs in this folder | accepted |
| [0002](0002-package-layout-and-toolchain.md) | Package layout and toolchain: Swift 6.2, strict concurrency | accepted; dependency and logging parts superseded by 0009, product and Linux parts by 0011 |
| [0003](0003-error-model.md) | One error type, `PassportError`, classified by the OAuth `error` code | accepted |
| [0004](0004-granted-scope-and-acceptance-policy.md) | Expose the granted scope; an acceptance policy decides before a token becomes current | accepted |
| [0005](0005-refresh-token-lane.md) | Operations that send the refresh token run one at a time | accepted; amended by 0007 |
| [0006](0006-injected-clocks.md) | Durations on an injected clock, not instants | accepted |
| [0007](0007-ordered-store-changes-and-session-lanes.md) | Ordered store changes, a lane per session, revocation of the newest token | accepted |
| [0008](0008-public-api-conventions.md) | Public API conventions: open structs for growing sets, factories, labels, `Duration`, `Secret` | accepted |
| [0009](0009-external-dependencies.md) | Which external dependencies are allowed and how they are chosen | accepted; amended by 0011 |
| [0010](0010-http-types.md) | swift-http-types is the HTTP currency type | accepted; amended by 0011 |
| [0011](0011-apple-platforms-only.md) | Apple platforms only: one module, CryptoKit, macOS 14 and iOS 17 | accepted |
| [0012](0012-strict-https-for-endpoints.md) | Endpoints must be `https`; loopback `http` needs the explicit `allowsInsecureLoopbackEndpoints` opt-in | accepted |
| [0013](0013-code-flow-requires-an-issuer.md) | The authorization code flow requires a configured issuer, so `iss` is never accepted unchecked | accepted |
