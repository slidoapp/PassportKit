# 0012. Strict HTTPS for endpoints, opt-in for loopback development

- Status: accepted
- Date: 2026-10-15

## Context

RFC 6749 §3.1 and §3.2 require TLS for the authorization and token endpoints, RFC 7009 §2.1 for revocation and
RFC 8414 §3 for metadata retrieval. PassportKit accepted plain `http` on any loopback host (`localhost`,
`127.0.0.1`, `::1`) without being asked, which the RFC matrix recorded as a deviation (TLS-1). The host name is a weak
signal: the app did not choose the exception, and a hard-coded or server-provided `http://localhost` endpoint would be
accepted in a release build. RFC 8252 §7.3 is a different matter: it allows an `http` loopback redirect URI because the
redirect carries no client credentials to a remote party and the listener is local to the device. That permission is
about redirect URIs and does not extend to endpoints that receive the client secret, authorization codes or tokens.

## Decision

- Every protocol endpoint, the issuer and the metadata URL must be `https`.
- `ClientConfiguration.allowsInsecureLoopbackEndpoints` (default `false`) is the one explicit opt-in. With it, an
  `http` URL whose host is `localhost`, `127.0.0.1` or `::1` is accepted. A non-loopback `http` URL is refused with or
  without it. The name follows ADR 0008: a Boolean that reads as a statement at the call site, and `Endpoints`
  rather than `URLs` because that is the term the RFCs and this API use for the server's URLs.
- The same parameter is accepted where a URL is validated before a configuration exists:
  `Discovery.fetchMetadata(issuer:allowsInsecureLoopbackEndpoints:…)`, `Endpoints.init(metadata:allowsInsecureLoopbackEndpoints:)` and
  `ClientConfiguration.init(metadata:…allowsInsecureLoopbackEndpoints:)`. Passing it to one does not imply the others,
  but the configuration stores it so the client does not need a second source of truth.
- Verification URIs of the device flow and the resource URLs a `RequestAuthorizer` signs follow the same rule through
  the configuration of the manager's client: both put a credential or a code in front of a person or a server, and a
  second, implicit policy would be surprising.
- Redirect URIs keep the RFC 8252 §7.3 rule (`http` only on a loopback host) and are not affected by the opt-in.
- Violations throw `.invalidConfiguration`; the message tells the app to opt in to insecure loopback endpoints.

## Consequences

Apps and tests that talk to a local `http` server (the integration tests, the example executable through
`--allow-insecure-loopback`) must opt in; this is a breaking change before 1.0. A release build that never sets the
flag cannot be pointed at a cleartext endpoint by configuration or metadata alone. We gave up a single flag per
endpoint kind: one switch is easier to audit, and local development servers use `http` for all endpoints at once.
