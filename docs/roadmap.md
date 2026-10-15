# Roadmap

Open work and deliberate omissions. Nothing here blocks a release; each item needs a design and, when it adds an
extension point or changes public API shape, an ADR before work starts. Shipped work is in `CHANGELOG.md`; protocol
features left out on purpose are `not planned` rows in `docs/rfc-matrix.md`.

## Follow-ups

- **Fix the SwiftKeychain write path upstream.** `KeychainCredentialStore` can lose the credential because
  SwiftKeychain replaces an item by deleting and adding it (ADR 0009, `docs/security-model.md`). The fix replaces
  delete-then-add with `SecItemUpdate`, then adds on `errSecItemNotFound`, and throws typed errors instead of archiving
  with `try?`. Afterwards restore the multi-store race test (a known issue now) and consider the data protection
  keychain.
- **Client credentials target in `TokenManager`.** Cache and coalesce machine-to-machine tokens (RFC 6749 §4.4) the way
  user tokens are, with a target derivation of its own and no refresh token or session.
- **`OAuthClient(issuer:)`.** An asynchronous convenience that runs discovery (RFC 8414) and builds the configuration,
  so the common case is one call.
- **Presentation options for `AuthorizationUserAgent`.** A struct that carries per-request choices, such as an
  ephemeral browser session or a presentation anchor, instead of more parameters on `present`.
- **A `Dependencies` struct for the seams.** Bundle the transport, clocks, random source and observer that
  `OAuthClient` takes as separate parameters into one value.
- **An AsyncHTTPClient transport.** `HTTPTransport` speaks swift-http-types (ADR 0010), so a transport for
  server-side Swift is a small adapter. It would live in its own target so the core does not link swift-nio, and it
  needs an ADR 0009 review. Linux itself stays out of scope (ADR 0011).
- **Rate limit for 401-triggered invalidation.** A resource that answers 401 `invalid_token` to every fresh token costs
  one refresh per request. A limit needs a policy for what to do over it; apps can wrap `RequestAuthorizer.evaluate`
  today (`docs/security-model.md`, known limits).

## Not planned

DPoP (RFC 9449), pushed authorization requests (RFC 9126), token introspection (RFC 7662), OpenID Connect ID token
validation, dynamic client registration, implicit and password grants. See `docs/spec.md` §1.
