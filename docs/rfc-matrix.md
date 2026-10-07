# RFC Traceability Matrix

Every protocol behaviour in PassportKit maps to a row here. Add or update
rows in the same change as the code and its test.

Status values: `planned`, `partial`, `done`, `not planned` (give the
reason in Notes).

## Scope

| RFC | Title | Status | Notes |
|---|---|---|---|
| 6749 | OAuth 2.0 Authorization Framework | planned | Authorization code, refresh, client credentials. No implicit or password grants. |
| 6750 | Bearer Token Usage | planned | Authorization header only; `WWW-Authenticate` challenge parsing. |
| 7636 | PKCE | planned | S256 always; `plain` not supported. |
| 8252 | OAuth 2.0 for Native Apps | planned | System browser, loopback and claimed HTTPS redirects. |
| 8628 | Device Authorization Grant | planned | |
| 8693 | Token Exchange | planned | Access-token and refresh-token subjects. |
| 8707 | Resource Indicators | planned | |
| 8414 | Authorization Server Metadata | planned | Configurable issuer validation. |
| 7009 | Token Revocation | planned | |
| 9207 | Authorization Server Issuer Identification | planned | |
| 9700 | OAuth 2.0 Security Best Current Practice | planned | Applied across all flows. |
| 7662 | Token Introspection | not planned | Resource-server concern. |
| 9449 | DPoP | not planned | Candidate for a later version. |
| 9126 | Pushed Authorization Requests | not planned | Candidate for a later version. |

## Requirements

| ID | RFC § | Level | Requirement | Status | Code | Test |
|---|---|---|---|---|---|---|
| | | | | | | |
