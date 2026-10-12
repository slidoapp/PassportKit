# 0010. HTTP currency types from swift-http-types

- Status: accepted
- Date: 2026-10-12

## Context

PassportKit defined its own `HTTPMethod`, `HTTPHeaders`, `HTTPRequest` and
`HTTPResponse`. They were small, but every transport author and every app that
signs requests had to learn them and convert to and from `URLRequest`, the
types of their server framework or swift-openapi-runtime. ADR 0009 already
prefers well-maintained Apple packages for protocol currency types.
[swift-http-types](https://github.com/apple/swift-http-types) is Apple's
(`HTTPRequest`, `HTTPResponse`, `HTTPFields`, `HTTPField.Name`), is the
currency of swift-openapi-runtime and of server frameworks such as
Hummingbird, and ships URLSession conversions in `HTTPTypesFoundation`.

## Suitability check

Checked before any code was migrated (swift-http-types 1.8.0 unless noted).

- **License, size, dependencies.** Apache 2.0, maintained by Apple, no
  dependencies of its own, two small targets (`HTTPTypes`,
  `HTTPTypesFoundation`).
- **Platforms.** Its manifest declares no platform floor (availability macros
  say macOS 10.0). `HTTPTypesFoundation` built for macOS 14, iOS 17, tvOS 17,
  watchOS 10 and visionOS 1 with `xcodebuild` and those deployment targets, and
  so did the migrated `PassportKit` target. Its CI also builds Linux and
  Windows; that no longer matters to PassportKit ([0011](0011-apple-platforms-only.md)).
- **URLSession conversion.** (Written when Linux was supported; Linux
  notes are superseded by [0011](0011-apple-platforms-only.md).)
  `HTTPTypesFoundation` provides `URLRequest(httpRequest:)`,
  `URLRequest.httpRequest`, `HTTPURLResponse.httpResponse` and
  `HTTPURLResponse(httpResponse:url:)`. Repeated header lines are
  merged with `", "` (`"; "` for `Cookie`); `URLSession` merges response
  lines the same way, so `WWW-Authenticate` challenges still arrive as one
  value, as before.
- **URL handling.** `HTTPRequest(method:url:headerFields:)` and `url` split a
  URL into scheme, authority and path pseudo header fields. The query stays in
  the path, the fragment and userinfo are dropped (the authority is host and
  port only), which is what is sent on the wire anyway. A URL without a scheme
  can trap in the initializer; the library only builds requests from endpoints
  that were validated as `https` or loopback `http`, and `RequestAuthorizer`
  checks the URL before it signs. The initializer and `url` live in
  `HTTPTypes` from 1.5.0 (trait `FoundationURL`, on by default); before that
  they needed `HTTPTypesFoundation` in every file.
- **Redaction. The unsuitable part, which we handle ourselves.** Measured with
  `print`, `String(reflecting:)` and `dump` on a request with an
  `Authorization` field and a query:
  - `HTTPFields` prints every field with its value in `description` and
    `debugDescription`, and `dump` shows them again through `_fields`.
  - `HTTPRequest` has a `debugDescription` of method, scheme, authority and
    path **with query** (`(POST) https://as.example.com/token?code=...`); it
    has no `description`, so `print` falls back to it. Its header fields are
    not in that line, but `dump` shows all of them.
  - `HTTPResponse` prints its status; `dump` shows its fields.
  - Nothing can be configured; the types are not redacting and cannot be made
    so from outside.
- **HPACK.** `HTTPField.indexingStrategy = .disallow` is the never-indexed
  marking (RFC 7541 §7.1.3); the library applies it to `Authorization`.

Verdict: suitable, provided PassportKit never lets a public type hold or
print these values unredacted (below). The cost of the redaction rule is the
reason the types are not re-exported: `HTTPFields` in a public property
exposes values to any `dump`.

## Decision

Depend on swift-http-types with `from: "1.5.0"` (products `HTTPTypes` and
`HTTPTypesFoundation`, linked into `PassportKit`; `HTTPTypes` also into
`PassportKitTesting` and the test targets). 1.5.0 is the first version that
has the URL conveniences in `HTTPTypes`; every 1.x above it is accepted, so a
consumer that already resolves any later 1.x does not conflict. A major
version is the only upper boundary, as ADR 0009 requires.

Delete `HTTPMethod`, `HTTPHeaders`, `HTTPRequest` and `HTTPResponse`.

**Transport shape.** As swift-openapi-runtime's `ClientTransport` does, the
request and response types carry no body and the body travels beside them:

```swift
public protocol HTTPTransport: Sendable {
    func send(_ request: HTTPRequest, body: Data?) async throws -> (HTTPResponse, Data)
}
```

- `request` has an absolute URL (`HTTPRequest(method:url:headerFields:)`).
  `baseURL` and `operationID`, which `ClientTransport` takes, have no meaning
  here: every URL is absolute and the library has no operations.
- The body is `Data`, not a streaming type: bodies are small forms and JSON,
  and the response body is capped at 1 MiB.
- The response body is a non-optional `Data` (empty for no body), so callers
  do not unwrap what the protocol always has.
- `RequestAuthorizer.send(_:body:for:)` mirrors it and returns
  `(HTTPResponse, Data)`.

**Names.** Public API that took `HTTPHeaders` takes `HTTPFields`
(`ClientConfiguration.additionalHeaders`, `RequestAuthorizer.evaluate`).
`AuthenticationChallenge.parse` keeps `[String]`, which is what
`fields[values: .wwwAuthenticate]` returns. The recording types of
`PassportKitTesting` expose `headerFields`, as `HTTPRequest` does.

**Redaction.** The security model's rule (no header value through
`description`, `debugDescription` or reflection) is kept like this:

- Every public type that *stores* `HTTPFields` or a request or response
  gets a redacting `description` and `debugDescription` and a `customMirror`
  that shows header names only: `ClientConfiguration`, `RecordedRequest`,
  `RecordingTransport.Step`, `FakeAuthorizationServer.ResponseOverride`.
  Their summaries use a `package` helper (`HTTPFields.names`) and
  `URL.redactedTarget`, which replace the former per-type code.
- Types the library only *hands back* are the caller's values and print like
  any `HTTPTypes` value: the signed `HTTPRequest` of `sign`, the response of
  `send`, the `request` property of `RecordedRequest`. This is documented on
  those members and in the articles: apps must not log a signed request.
  `RequestAuthorizer`, `OAuthClient` and the transports hold no fields.
- The library marks `Authorization` (Basic client authentication, Bearer
  signing) with `indexingStrategy = .disallow`.
- Inside the library, headers, requests and responses are never logged or put
  into errors; this was already the rule and the redaction canary enforces
  it: it now gives `ClientConfiguration` an additional header whose value is a
  canary, and keeps covering every flow.

**URLSessionTransport** converts with `URLRequest(httpRequest:)` and
`HTTPURLResponse.httpResponse`. Redirect handling stays on `URLRequest`
(`RedirectPolicy`), so POST no-redirect, the https to http refusal, the
cross-origin header stripping, the body cap, timeouts and late-cancel
delivery are unchanged. `RequestAuthorizer.data(for:target:session:)` keeps
its `URLRequest` convenience.

## Consequences

Apps and transports use types they may already know, and an adapter to
another HTTP client is a small transport, because the types are shared across
the ecosystem; a transport on AsyncHTTPClient is listed in the plan as an
option, not built. Consumers `import HTTPTypes` to implement a transport
or build a request. `ClientConfiguration` is no longer a plain struct for
reflection purposes: `dump` shows the header names, not the values. Header
field names are `HTTPField.Name` values, which cannot hold an invalid name;
invalid values are sanitized by `HTTPField`. There is no longer a
`Hashable` request or response in PassportKit.

Two limits stay. ~~Linux is verified by CI, not locally.~~ The caller owns the
redaction of what we hand back. `URLRequest(httpRequest:)` merges repeated
request header lines into one, as `URLSession` does on the wire.
