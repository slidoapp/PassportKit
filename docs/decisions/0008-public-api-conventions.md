# 0008. Public API conventions

- Status: accepted
- Date: 2026-10-08

## Context

An API review before the first release found names and shapes that would
be expensive to change later: closed enums that will gain cases, a case
called `none` next to `Optional.none`, a method that clashed in name with
a different operation, closures where a named type could grow, and
`TimeInterval`, `Int` seconds and `Duration` side by side. After 1.0
each of these is a source break, so they were settled while breaking
changes are free. The conventions are recorded so later additions follow
them. They follow the Swift API Design Guidelines and `AGENTS.md`.

## Decision

- **Open structs for sets that grow, enums for closed outcomes.** A type
  whose values come from a registry, a specification that adds values,
  or the library's own roadmap is a struct with a `rawValue` or private
  storage and `static` members, like `GrantType`: `ClientAuthentication`,
  `TokenTarget.Derivation`, `EndpointKind`, `TokenTypeHint`,
  `AuthorizationRequest.Prompt`, `TargetSelector`. A type that describes a
  closed outcome the caller must handle stays an enum and is documented
  as not frozen, so callers switch with a `default`: `Recovery`,
  `RetryDecision`, `SessionEvent`, `SignOutReason`,
  `SignOutResult.Revocation`.
- **Factories and names that cannot collide.** A case that would be
  called `none` is named for what it does: `.publicClient(clientID:)`,
  `.noAction`, `.noInteraction` (the wire value `none`). Creating a value
  with several valid shapes goes through factories that cover exactly the
  valid combinations (`TokenTarget.refreshGrant(...)`, `.exchange(...)`);
  the memberwise initializer is `package`.
- **Parameter objects instead of closures and long argument lists.** An
  extension point receives one struct (`TokenAcceptanceContext`) so a
  member can be added without breaking implementations. A choice among
  behaviours is a named, open type (`TargetSelector`) rather than a bare
  closure; a closure form stays available (`.matching`, `.custom`).
- **Labels.** The first argument is unlabeled when the call reads as a
  phrase about it (`refresh(_ refreshToken:)`, `sign(_ request:for:)`);
  `for:` names a target, `using:` a collaborator that does the work for
  one call, and collaborators that live as long as the value are
  initializer parameters (`RequestAuthorizer(manager:transport:)`).
  Parameters that hold several values are plural (`audiences`,
  `resources`) and arrays default to `[]`.
- **Verb pairs.** A flow that spans user interaction has `begin...` and
  `complete...` (`beginAuthorization`/`completeAuthorization`,
  `beginDeviceAuthorization`/`completeDeviceAuthorization`), and a single
  call that does both is named after the flow (`authorize`). A method
  that only adds a header is `sign`, never `authorize`. Collections that
  grow by one are `append(_ name:, _ value:)`, for headers and for
  additional parameters alike.
- **`Duration` everywhere.** Every length of time in the public API,
  including the testing module, is a `Duration`. `TimeInterval` appears
  only where Foundation requires it (`Date` arithmetic), internally.
- **`Secret` for credential values.** Parameters and properties that hold
  a token, code, verifier or client secret are `Secret`. Convenience
  overloads that take `String` exist only where tests read raw response
  bodies (`FakeAuthorizationServer.expire(token:)` and its siblings).
- **Accidental surface stays internal.** Constants and helpers that the
  library itself uses are internal; test-only access uses `@testable` or
  `package`. Values the library issues (`AccessToken`) have a `package`
  initializer and read-only members that carry its bookkeeping.
- **`LocalizedError` owns `errorDescription`.** `PassportError` conforms,
  and its `errorDescription` is the redacted `description`. The sanitized
  server text is `detail`.

## Consequences

Callers can rely on source-compatible minor releases when types grow, and
switch statements over non-frozen enums need a `default`. Open structs
lose exhaustiveness checking for their own members, which is the price of
evolvability and is why only registries and roadmap-driven sets use them.
Types that hold a transport (`RequestAuthorizer`) must keep a fixed
description, because the canary test dumps them around fakes that hold
secrets. The one-time cost was a breaking change to every call site, test,
article and snippet before the first release.
