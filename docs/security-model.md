# Security model

What must never leak, which threats the library covers and where its limits are. Report vulnerabilities as
described in [SECURITY.md](../SECURITY.md).

## Secrets

Secrets are: access tokens, refresh tokens, ID tokens, authorization
codes, PKCE verifiers, device codes, client secrets.

- Never logged, printed, or included in errors, `description`,
  `debugDescription`, or observability events.
- Types that hold secrets have redacting `description` and
  `debugDescription`.
- Never placed in URLs (query or fragment) except where an RFC requires
  it (the authorization code in a redirect).

`Secret` encodes as a plaintext string, because credential stores must
persist the real value. Redaction covers `description`, `debugDescription`
and reflection only. Encode a `Secret` solely into secure storage, never
into logs, analytics, crash reports or unprotected files. `Secret ==` is
not constant time; the library compares `state` in constant time itself.

HTTP header values can carry credentials (`Authorization`, `Cookie`, API keys), and swift-http-types prints them:
`HTTPFields` shows every value in `description`, `debugDescription` and `dump`, and `HTTPRequest` shows its URL with
query. Public PassportKit types that store header fields (`ClientConfiguration`, `RecordedRequest` and the scripted
responses of `PassportKitTesting`) therefore have redacting descriptions and mirrors that show header names only.
A signed `HTTPRequest` or a response that the library returns is the caller's value and prints like any
`HTTPTypes` value: do not log it. The library marks `Authorization` as never indexed (RFC 7541 §7.1.3).

A server can make a library repeat what it was sent, for example by echoing
a token in `error_description`. Every credential of a request (refresh,
subject and actor tokens, authorization code, PKCE verifier, device code,
client secret, the token of a revocation, the bearer token of a resource
request) is therefore replaced by `<redacted>` in the error built from the
response, whatever its length. `dump` of an `OAuthClient` shows a summary, so
it cannot reach the injected transport or observer.

Text that arrives from the network and may reach a log or a UI is
untrusted: error codes must match RFC 6749 §5.2 and fit 64 characters or
the response is `invalidResponse`; `error_uri` keeps only `http` and
`https`; `error_description` loses control, line-separator and invisible
format characters (bidirectional overrides), long token-like runs and
everything past 200 characters.

## Logging

Logs go through swift-log (`logger:` parameters, see `docs/spec.md`) and
follow the same rules as errors and events:

- Messages are constant strings; data goes in metadata.
- Only low-cardinality, non-secret metadata: endpoint kind, grant type,
  HTTP status, the sanitized OAuth `error` code, duration, session
  reason, Keychain `OSStatus`.
- Never tokens, authorization codes, `state`, PKCE verifiers, device
  codes, client secrets, URLs with a query, headers, request or response
  bodies, or a server's `error_description`.
- A new log line needs the redaction canary to cover its path: the test
  captures every line of a run with a test `LogHandler` and searches
  messages and metadata values for the canaries.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Authorization code interception | PKCE with S256 on every authorization code flow (RFC 7636, RFC 9700) |
| CSRF on redirect | `state` generated per request and validated exactly |
| Mix-up attacks | The code flow needs a configured issuer and compares the response `iss` with it exactly (RFC 9207 §2.4); the response parameter is required when the server advertises it. Servers without RFC 9207 need another defence (a distinct redirect URI per authorization server, RFC 9700 §4.4.2); the device flow has no authorization response and is not affected |
| Open redirect / redirect injection | Exact redirect URI matching; loopback listener binds to loopback interfaces only |
| Web page races or floods the loopback listener | The listener claims only a `GET` for its path with the loopback `Host`, `state` and `code` or `error`, no background `Sec-Fetch-*` metadata and an `accept` match on `state`; at most 8 connections, closed after 5 s, on `cancel()` and on delivery; a released listener stops (RFC 8252 §8.3) |
| Token sent to an attacker-chosen host | `RequestAuthorizer` sends only over `https` (loopback `http` only with the opt-in `allowsInsecureLoopbackEndpoints`); `allowedOrigins` limits the hosts, and must be set when request URLs come from untrusted data; redirects never leave HTTPS and drop credential headers across origins, also for `data(for:target:session:)` |
| Header injection through a token | A token that is not a `b64token` (RFC 6750 §2.1) is refused before it reaches a header |
| Memory growth from many targets | The token cache and the remembered rejections are limited to 256 entries each |
| Server text shown to a person | Error text is sanitized; a device `user_code` with control or invisible characters, or over 64 characters, is an invalid response; apps show it themselves (RFC 8628 §3.3), and the example executable prints server text through a sanitizer |
| Token theft from logs | Redaction rules above, enforced by tests and by the redaction canary, which searches every error, event, log line and description of every flow for the secrets it used |
| Token sent with the wrong scheme | Only `Bearer` tokens are sent by `RequestAuthorizer`; sender-constrained types fail before any request |
| Token theft from storage | Platform secure storage (Keychain) with the strictest workable accessibility class, enforced on iOS; the macOS login keychain does not enforce it (Known limits) |
| Refresh token replay after rotation | Persist rotated refresh token before use; serialize refresh-token-consuming operations |
| Token used for the wrong resource | Tokens bound to their resource indicator; never reused across resources |
| Insufficient token treated as valid | Granted scope recorded; app-supplied acceptance hook runs before a token becomes current |

## Transport

- HTTPS for every protocol endpoint (authorization, token, device authorization, revocation, discovery and the
  endpoints in fetched metadata), the issuer and tokens sent to resources (RFC 6749 §3.1, §3.2, RFC 7009 §2.1,
  RFC 8414 §3). Plain `http` is never implied by a host name: an app that talks to a local development server
  sets `ClientConfiguration.allowsInsecureLoopbackEndpoints` (and passes it to `Discovery.fetchMetadata`), which
  admits `http` on `localhost`, `127.0.0.1` and `::1` only; any other `http` URL is refused with or without it
  (ADR 0012). Redirect URIs are not endpoints: the RFC 8252 §7.3 `http` loopback redirect URI needs no opt-in,
  because no credential is sent to it. The `localhost` name is also
  accepted in a redirect URI although RFC 8252 §7.3 says NOT RECOMMENDED (RFC 8252 §8.3 prefers the IP literal);
  the library's own listener uses `127.0.0.1`.
- Token requests do not follow redirects.
- Other redirects never leave HTTPS for HTTP. When a redirect changes
  scheme, host or port, every request header except `Accept`,
  `Accept-Language` and `User-Agent` is dropped.
- Requests time out after 30 s of silence and 60 s in total (configurable).
- Additional parameters can never carry `client_id` or `client_secret`
  (RFC 6749 §2.3: one authentication method per request).
- A verification URI shown to a person must be `https` (loopback `http` only with the opt-in).

## Known limits

- **The Keychain write path can lose the credential.** `KeychainCredentialStore` is built on SwiftKeychain, which
  replaces an existing item by deleting it and adding it again. If the add fails (device locked, denied prompt,
  entitlement problem) or the process dies in between, the stored credential is gone; with refresh token rotation the
  replaced token is already invalid, so the user must sign in again. Stores writing one item at once can fail the
  same way, and the payload is archived with `try?`. See ADR 0009; the fix is an upstream
  update-then-add change (`docs/roadmap.md`).
- **The macOS login keychain does not enforce accessibility or access groups.** On macOS `KeychainCredentialStore`
  uses the file-based login keychain, because SwiftKeychain cannot target the data protection keychain. There
  `Accessibility` and `accessGroup` are accepted but not enforced: an item is readable whenever the login keychain
  is unlocked, and the access group does not separate apps. What protects the item is the keychain's access control
  for the app that created it. On iOS both are enforced. The store sets `kSecAttrSynchronizable` to `false` on every
  operation, so a credential never reaches iCloud Keychain on either platform.
- **ID tokens are stored, never validated.** PassportKit is an OAuth 2.0 client, not an OpenID Connect relying
  party: an `id_token` is kept in the credential without checking its signature, issuer, audience or nonce. Do not
  treat it as proof of identity.
- **401-triggered invalidation is not rate limited.** A resource that answers 401 `invalid_token` to every fresh
  token makes each request cost one refresh (a request retries once; concurrent requests for the same token share
  one refresh). A rate limit needs a policy for what to do over the limit and is left to the app, which can wrap
  `RequestAuthorizer.evaluate` or stop on repeated `unauthorized` errors.
