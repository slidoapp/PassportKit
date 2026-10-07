# Error handling

PassportKit throws one error type, ``PassportError``, and tells you what to do
next.

## Code and recovery

``PassportError/code`` says what happened. It preserves the server's OAuth
error code (RFC 6749 §5.2, RFC 8628 §3.5, RFC 8707 §2, RFC 6750 §3.1) and adds
client-side codes such as ``PassportError/Code-swift.struct/invalidResponse``
or ``PassportError/Code-swift.struct/stateMismatch``. The set is open: a code
the library does not know is kept verbatim.

``PassportError/recovery`` says what to do. Branch on the recovery, not on
the code, unless you have a reason to treat one code specially:

```swift
func handle(_ error: PassportError) {
    switch error.recovery {
    case .reauthenticate:
        // The root grant is gone. Show the sign-in screen.
        break
    case .resourceDenied:
        // This resource or audience is not available to this person. The session is fine.
        break
    case .retryLater(let after):
        // A transient failure. Retry no sooner than `after` when the server gave one.
        _ = after
    case .fixConfiguration:
        // A bug in the client setup or the request. Retrying cannot help; log it.
        break
    case .none:
        // Nothing to recover from, for example the person declined.
        break
    }
}
```

| Recovery | Typical codes | What to do |
|---|---|---|
| ``PassportError/Recovery-swift.enum/reauthenticate`` | `invalid_grant` on refresh, `expired_token` in the device flow, `not_authenticated` | Ask the person to sign in again. For a refresh failure the session has already ended. |
| ``PassportError/Recovery-swift.enum/resourceDenied`` | `access_denied`, `invalid_target`, `insufficient_scope`, `token_rejected`, `unauthorized` | Treat the resource as unavailable. Keep the session and everything else working. |
| ``PassportError/Recovery-swift.enum/retryLater(after:)`` | `temporarily_unavailable`, `server_error`, `transport_failure` | Retry with back-off, no sooner than `after`. |
| ``PassportError/Recovery-swift.enum/fixConfiguration`` | `invalid_client`, `unauthorized_client`, `unsupported_grant_type`, `invalid_request`, `invalid_scope`, `invalid_configuration` | Do not retry. The client registration, the configuration or the request is wrong. |
| ``PassportError/Recovery-swift.enum/none`` | `access_denied` when the person declined, `user_cancelled`, `invalid_response` | Nothing to do or retry; report if unexpected. |

Classification follows the `error` member of the response body, not the HTTP
status (RFC 6749 §5.2). The status is recorded in ``PassportError/statusCode``
for diagnostics only. A response that is not an OAuth error maps by status:
429 and 5xx are retryable, anything else is ``PassportError/Code-swift.struct/invalidResponse``.

## Server text is untrusted

``PassportError/errorDescription`` and ``PassportError/errorURI`` come from
the network. The description has control and invisible characters removed, is
cut to 200 characters, and has token-like runs and the credentials the library
sent replaced by `<redacted>`. `errorURI` keeps only `http` and `https`
links. Show the description for diagnostics, never branch on it, and never put it into
a place that interprets markup.

## Cancellation

A cancelled task throws `CancellationError`, not a ``PassportError``. A person
who dismisses the sign-in sheet gets
``PassportError/Code-swift.struct/userCancelled``.

## Sessions

``TokenManager`` reports the end of a session as an event as well as an
error, so one place can react. Observe it instead of checking every call:

```swift
func watch(_ manager: TokenManager) async {
    for await event in manager.events {
        if case .signedOut(let reason) = event {
            print("Signed out: \(reason)")
        }
    }
}
```

## Logging

Descriptions of errors, events and every public value hide credentials. Use
a ``PassportObserver`` to see requests, response codes and durations without
bodies or secrets.
