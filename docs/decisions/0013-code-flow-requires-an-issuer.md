# 0013. The authorization code flow requires an expected issuer

- Status: accepted
- Date: 2026-10-15

## Context

A mix-up attack makes a client send an authorization code, or use a response, with the wrong authorization server
(RFC 9700 section 4.4.2). RFC 9207 section 2.4 defends against it by having the client compare the `iss` parameter of
every authorization response, errors included, with the issuer it started the flow with, by exact string comparison.
PassportKit did the comparison only when `ClientConfiguration.issuer` was set and accepted any `iss` otherwise, and
accepted a missing `iss` unless `requiresIssuerInAuthorizationResponse` was set. A configuration without an issuer
therefore looked protected and was not.

## Decision

- `beginAuthorization`, `authorize` and `completeAuthorization` throw `.invalidConfiguration` when
  `ClientConfiguration.issuer` is `nil`. `completeAuthorization` checks it first, before the pending authorization is
  consumed and before any request, so a client built without an issuer cannot redeem a code.
- The comparison stays exact (RFC 9207 section 2.4), and `requiresIssuerInAuthorizationResponse` stays the switch
  for a missing `iss`; configurations built from metadata set it from `authorization_response_iss_parameter_supported`.
- No separate policy type. The prerequisite is a plain precondition, and a strict mode that required `iss` for servers
  that cannot send it would make those servers unusable. Servers without RFC 9207 need another defence, which the app
  owns, typically a distinct redirect URI per authorization server (RFC 9700 section 4.4.2); the documentation says so.
- The device flow has no authorization response and is not affected.

## Consequences

Apps that assembled a `ClientConfiguration` by hand without `issuer` must set it; discovery already did. An
authorization response `iss` is never accepted unchecked. For a server that does not advertise RFC 9207 the library
cannot detect a mix-up; that gap is documented, not hidden.
