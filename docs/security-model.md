# Security Model

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

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Authorization code interception | PKCE with S256 on every authorization code flow (RFC 7636, RFC 9700) |
| CSRF on redirect | `state` generated per request and validated exactly |
| Mix-up attacks | Validate `iss` in the authorization response when present (RFC 9207) |
| Open redirect / redirect injection | Exact redirect URI matching; loopback listener binds to loopback interfaces only |
| Web page races or floods the loopback listener | The listener claims only a `GET` for its path with the loopback `Host`, `state` and `code` or `error`, no background `Sec-Fetch-*` metadata and an `accept` match on `state`; at most 8 connections, closed after 5 s, on `cancel()` and on delivery; a released listener stops (RFC 8252 §8.3) |
| Token sent to an attacker-chosen host | `RequestAuthorizer` sends only over `https` or to loopback; `allowedOrigins` limits the hosts, and must be set when request URLs come from untrusted data; redirects never leave HTTPS and drop credential headers across origins, also for `data(for:target:session:)` |
| Header injection through a token | A token that is not a `b64token` (RFC 6750 §2.1) is refused before it reaches a header |
| Memory growth from many targets | The token cache and the remembered rejections are limited to 256 entries each |
| Server text shown to a person | Error text is sanitized; a device `user_code` with control or invisible characters, or over 64 characters, is an invalid response; apps show it themselves (RFC 8628 §3.3), and the example executable prints server text through a sanitizer |
| Token theft from logs | Redaction rules above, enforced by tests and by the redaction canary, which searches every error, event and description of every flow for the secrets it used |
| Token sent with the wrong scheme | Only `Bearer` tokens are sent by `RequestAuthorizer`; sender-constrained types fail before any request |
| Token theft from storage | Platform secure storage (Keychain) with the strictest workable accessibility class |
| Refresh token replay after rotation | Persist rotated refresh token before use; serialize refresh-token-consuming operations |
| Token used for the wrong resource | Tokens bound to their resource indicator; never reused across resources |
| Insufficient token treated as valid | Granted scope recorded; app-supplied acceptance hook runs before a token becomes current |

## Transport

- HTTPS for all endpoints and for tokens sent to resources. Two loopback exceptions: redirect URIs
  (RFC 8252 §7.3) and, as a development deviation from RFC 6749 §3.1, §3.2, RFC 7009 §2.1 and RFC 8414 §3,
  endpoints and resources on a loopback host (`localhost`, `127.0.0.1`, `::1`). The `localhost` name is also
  accepted in a redirect URI although RFC 8252 §7.3 says NOT RECOMMENDED (RFC 8252 §8.3 prefers the IP literal);
  the library's own listener uses `127.0.0.1`.
- Token requests do not follow redirects.
- Other redirects never leave HTTPS for HTTP. When a redirect changes
  scheme, host or port, every request header except `Accept`,
  `Accept-Language` and `User-Agent` is dropped.
- Requests time out after 30 s of silence and 60 s in total (configurable).
- Additional parameters can never carry `client_id` or `client_secret`
  (RFC 6749 §2.3: one authentication method per request).
- A verification URI shown to a person must be `https` (or loopback `http`).

## Known limits

- **ID tokens are stored, never validated.** PassportKit is an OAuth 2.0 client, not an OpenID Connect relying
  party: an `id_token` is kept in the credential without checking its signature, issuer, audience or nonce. Do not
  treat it as proof of identity.
- **401-triggered invalidation is not rate limited.** A resource that answers 401 `invalid_token` to every fresh
  token makes each request cost one refresh (a request retries once; concurrent requests for the same token share
  one refresh). A rate limit needs a policy for what to do over the limit and is left to the app, which can wrap
  `RequestAuthorizer.evaluate` or stop on repeated `unauthorized` errors.
