# 0016. Public API naming

- Status: accepted
- Date: 2026-11-19
- Amends: [0008](0008-public-api-conventions.md), for the name of the method that adds a token to a request

## Context

The leaf types of the 1.0 API were named consistently, but a developer could not tell from the names which of the
main objects to use. The session type was called `TokenManager` although every document called it a session. The
resource-side type `RequestAuthorizer` shared the verb "authorize" with `OAuthClient.authorize(_:using:)`, which signs
a person in, and its method `sign` suggested a cryptographic signature that a bearer token does not carry. Three
prefixes (`Passport`, `OAuth` and none) were used without a rule. Some members transliterated wire fields, and the
built-in stores and policies did not appear in autocomplete.

The library has no known consumers yet. The renames therefore ship as breaking changes in minor releases, without
deprecated aliases, and the 1.x promise of the 1.0.0 release is set aside for them.

## Decision

Each main object is named after the OAuth party it talks to, and each method after the action it performs.

| Party | Type | What it does |
|---|---|---|
| Authorization server | `OAuthClient` | It runs one-shot protocol requests and keeps no state. |
| The signed-in user | `OAuthSession` | It adopts the tokens a sign-in flow obtained, stores the refresh token, and refreshes and hands out access tokens. |
| Protected resource | `ProtectedResourceClient` | It adds the access token to requests, sends them and retries once after a 401. |

Prefixes appear only where they carry meaning. The `OAuth` prefix marks the two entry points, so they appear together
in autocomplete. `PassportError` is the only type with the library prefix, because a bare `Error` would collide with
Swift's protocol. Every other type has no prefix.

Names follow these rules:

1. **Roles get the developer's words, and protocol concepts keep their RFC names.** A type that plays a role for the
   app is named after that role. A protocol concept keeps the name developers search for, such as
   `ClientAuthentication`, `issuer`, `AuthorizationServerMetadata` or `TokenTypeHint`. The first DocC sentence cites
   the RFC section.
2. **Spelling follows Swift, and the protocol concept stays recognizable.** A wire field such as
   `authorization_response_iss_parameter_supported` gets an idiomatic Swift name, and the wire spelling stays in
   `CodingKeys` and `Core/WireNames.swift`.
3. **Subordinate types are nested, and reusable protocol concepts keep independent names.** A subordinate type is one
   the library invented that means nothing outside its owner, such as `OAuthSession.Event` or
   `ProtectedResourceClient.RetryDecision`. A reusable protocol concept is named by an RFC or a registry, or callers
   implement, construct, store or discuss it on their own. It stays top-level even when one type uses it, as
   `ClientAuthentication`, `Endpoints`, `IssuerValidation`, `TokenTypeHint` and `AuthenticationChallenge` do. The
   number of top-level types is not a goal.
4. **Grammar follows side effects.** Methods with side effects are verb phrases, such as `restore()` and
   `discard(_:)`, and members without side effects are noun phrases.
5. **Direct token requests have one entry point.** One method takes a value whose factories carry the grant type
   names. The `complete…` flow methods keep their own names, because they add redirect validation or polling around
   the token request.
6. **Extension points list their built-in implementations as static members**, so `store: .keychain()` and
   `acceptancePolicy: .custom { … }` appear in autocomplete after the dot.
7. **A label never borrows a word that means something else in the library.** The `URLSession` parameter is
   `urlSession:`, because "session" means the OAuth session.
8. **One concept has one name everywhere.** "Session" replaces "manager". "Revoke" is the RFC 7009 server call, and
   "discard" drops a cached token locally. A "time limit" ends a wait, and a "lifetime" is how long something stays
   valid.
9. **Paired flows share a shape.** A flow that waits for a person starts with `begin…`, returns a `Pending…` value
   and ends with `complete…`. A single call that does both is named after the flow (`authorize`).
10. **Lifecycle and event names describe the local change.** `OAuthSession.Event.accessTokenUpdated(target:)` says
    what changed in the session, and its DocC comment names the server operations behind it. The DocC comments of
    `signIn` and `signOut` say what they leave untouched at the authorization server.

Two labelling rules of ADR 0008 change:

- The method that adds the access token to a request and returns the changed copy is
  `addingToken(to:for:)`. The `-ing` form is the Swift convention for a method that returns a changed copy, and
  "authorize" stays reserved for the interactive flow. This replaces the ADR 0008 rule that such a method is
  called `sign`.
- `for:` names a token target in every method whose first argument is unlabeled. `data(for:target:urlSession:)`
  is the exception: its `for:` names the request, as in `URLSession.data(for:)`, so the target is `target:`.

## Consequences

The three main objects can be told apart by name, and the words "session", "authorize", "revoke" and "discard" each
have one meaning. Callers find the built-in stores through static members.

Every rename breaks source compatibility. Apps that depend on 1.0 must rename their call sites when they update.

When this decision was accepted, some 1.0 names did not follow rules 2, 5, 6 and 9: the token request methods of
`OAuthClient`, `DeviceAuthorization` and its `verificationURIComplete`, `ClientConfiguration`, `revoke(_:typeHint:)`,
`RequireAnyScope(_:forTargets:)`, `TargetSelector`, the labels of `Discovery.fetchMetadata` and the transliterated
members of `AuthorizationServerMetadata`. A separate change renamed them by these rules, and `CHANGELOG.md` lists the
new names.
