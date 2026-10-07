# PassportKit integration server

A local, fully scriptable OAuth 2.0 authorization server for integration-testing PassportKit.
Built on [`oidc-provider`](https://github.com/panva/node-oidc-provider) (pinned in `package.json`),
in-memory storage, no browser, no Docker.

## Run

```sh
cd Tools/integration-server
npm install
node server.js            # http://localhost:9400 (PORT overrides; issuer follows PORT, or set ISSUER)
./smoke.sh                # starts its own instance on port 9411 (SMOKE_PORT) and checks every flow
```

Environment: `PORT`, `ISSUER`, `ACCESS_TOKEN_TTL` (600 s), `REFRESH_TOKEN_TTL` (86400),
`AUTHORIZATION_CODE_TTL` (60), `DEVICE_CODE_TTL` (600).
One log line per request (`METHOD path status`), never queries, bodies or tokens.

## Endpoints

| Purpose | URL |
| --- | --- |
| Metadata (OIDC) | `/.well-known/openid-configuration` |
| Metadata (RFC 8414) | `/.well-known/oauth-authorization-server` (same document) |
| Authorization | `/auth` (PKCE S256 required; responses carry `iss`, RFC 9207) |
| Token | `/token` |
| Device authorization | `/device/auth` (user-facing pages at `/device`) |
| Revocation | `/token/revocation` (introspection is off) |

## Clients and scopes

Scopes: `openid offline_access profile email api:read api:write`.

| Client | Type | Grants / notes |
| --- | --- | --- |
| `public-native` | public, auth method `none` | `authorization_code`, `refresh_token`, device code, token exchange. Redirects `http://127.0.0.1/callback` (any port) and `com.example.app:/callback` |
| `audience-client` | public | `refresh_token` only; target of refresh-token exchange |
| `confidential-service` | secret `integration-secret` | `client_credentials`; basic or post authentication |

Resources: any `https://api.example.com/...` is accepted (opaque token, `aud` = the resource, scopes `api:read api:write`); anything else yields `invalid_target`.

## Test hooks

- **Auto interaction**: any `GET /interaction/:uid` logs in `test-user` and grants every requested scope/resource, then redirects onward. A client that follows redirects reaches the `redirect_uri` with `code`, `state`, `iss`. Request `prompt=consent` with `offline_access`, or `oidc-provider` drops `offline_access` and issues no refresh token.
- `POST /test/device/approve` with `{"user_code":"ABCD-EFGH"}` approves for `test-user`; `POST /test/device/deny` denies (`access_denied` on the next poll). Returns 400 for an unknown or used code. Implemented by driving the real `/device` pages internally.
- `POST /test/reset` wipes all stored tokens, grants, sessions and codes.

## Simulated behaviours

- **Refresh rotation + reuse detection**: each refresh returns a new refresh token; replaying an old one gives `invalid_grant` and revokes the whole grant.
- **Token exchange (RFC 8693)**, grant `urn:ietf:params:oauth:grant-type:token-exchange`, client `public-native` only:
  - `subject_token_type=...:access_token` with `resource`: issues an access token for that resource (scope = subject/requested scope within `api:*`). Resource containing `/denied/`: HTTP 401 `{"error":"access_denied"}`.
  - `subject_token_type=...:refresh_token` with `audience=audience-client`: the subject refresh token is consumed and its replacement returned in `refresh_token`; a new refresh token for the audience client is returned in `access_token` with `issued_token_type=...:refresh_token`, `token_type=N_A`. Replaying a consumed subject token revokes the grant. Without `audience`, you get an access token plus the rotated refresh token.
- **Underscoped 200**: a `refresh_token` grant naming a resource containing `/denied/` returns HTTP 200 with a fresh access token whose scope omits `api:read`/`api:write`. Done in `getResourceServerInfo`: for that route/resource it advertises only a dummy scope `api:none`, so `oidc-provider` filters the scopes. The denied resource is fully grantable at authorization time, so the narrowing is a refresh-time effect.

## Known gaps versus real servers

- Signing keys are `oidc-provider` development keys; storage is memory; sessions end on restart.
- No consent or login UI; no real user accounts (`test-user` only); `profile`/`email` claims are fixed.
- Metadata at the RFC 8414 path is the OIDC document (extra OIDC fields included, `token_endpoint`, `revocation_endpoint` etc. present).
- Exchanged tokens are not bound to the subject token's resource audience; actor tokens, `requested_token_type` and `may_act` are ignored.
- The device flow does not enforce polling `interval`/`slow_down`.
- Revocation does not restrict which client may revoke (default policy; logs a notice).
- Unknown scope values and resources outside `https://api.example.com/` are rejected exactly as `oidc-provider` does, with its error wording.
- No DPoP, mTLS, PAR, JAR, introspection, dynamic registration.
