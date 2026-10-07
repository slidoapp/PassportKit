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
| Token theft from logs | Redaction rules above, enforced by tests |
| Token theft from storage | Platform secure storage (Keychain) with the strictest workable accessibility class |
| Refresh token replay after rotation | Persist rotated refresh token before use; serialize refresh-token-consuming operations |
| Token used for the wrong resource | Tokens bound to their resource indicator; never reused across resources |
| Insufficient token treated as valid | Granted scope recorded; app-supplied acceptance hook runs before a token becomes current |

## Transport

- HTTPS only for all endpoints, except loopback redirect URIs (RFC 8252).
- Token requests do not follow redirects.
- Other redirects never leave HTTPS for HTTP. When a redirect changes
  scheme, host or port, every request header except `Accept`,
  `Accept-Language` and `User-Agent` is dropped.
- Requests time out after 30 s of silence and 60 s in total (configurable).
- Additional parameters can never carry `client_id` or `client_secret`
  (RFC 6749 §2.3: one authentication method per request).
- A verification URI shown to a person must be `https` (or loopback `http`).
