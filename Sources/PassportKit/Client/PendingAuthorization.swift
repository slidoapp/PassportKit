import Foundation

/// An authorization request that was started and awaits the redirect (RFC 6749 §4.1).
///
/// Open ``url`` in an external user agent, then pass the callback URL to
/// ``OAuthClient/completeAuthorization(_:callbackURL:additionalParameters:)``.
///
/// - Single use: the first callback that reaches the `state` check consumes the value, and a second
///   completion throws `invalidConfiguration`. Copies share this state. Callbacks rejected before that check
///   (wrong redirect, wrong `state`) do not consume it, so a stray request to a loopback listener cannot
///   cancel the real flow.
/// - Expires after ``AuthorizationRequest/lifetime`` (10 minutes by default), measured on the client's injected clock (ADR 0006); completing it
///   later throws `timedOut` with recovery `reauthenticate`.
/// - The description shows the redirect target and age only: neither `state` nor the PKCE verifier is printed.
public struct PendingAuthorization: Sendable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    /// The authorization URL to open in an external user agent. It contains `state` and the PKCE challenge,
    /// by design, so treat it as short-lived.
    public let url: URL
    /// The redirect URI of the request; the callback must match it.
    public let redirectURI: URL

    let state: Secret
    let codeVerifier: Secret
    /// The resource indicators of the authorization request, repeated on the token request (RFC 8707 §2.2).
    let resources: [URL]
    private let lifetime: Duration
    private let stopwatch: Stopwatch
    private let usage = SingleUse()

    init(
        url: URL, redirectURI: URL, state: Secret, codeVerifier: Secret, resources: [URL], lifetime: Duration,
        stopwatch: Stopwatch
    ) {
        self.url = url
        self.redirectURI = redirectURI
        self.state = state
        self.codeVerifier = codeVerifier
        self.resources = resources
        self.lifetime = lifetime
        self.stopwatch = stopwatch
    }

    var isExpired: Bool { stopwatch.elapsed >= lifetime }
    var isConsumed: Bool { usage.isClaimed }

    /// Marks the value used. Returns `false` when another completion already did.
    func consume() -> Bool { usage.claim() }

    /// A summary without `state`, verifier or the authorization URL.
    public var description: String {
        "PendingAuthorization(redirectURI: \(HTTPRequest.redactedTarget(of: redirectURI)), age: \(stopwatch.elapsed))"
    }

    /// A summary without `state`, verifier or the authorization URL.
    public var debugDescription: String { description }

    /// A mirror exposing the summary only.
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}

/// A flag shared by all copies of a ``PendingAuthorization``.
private final class SingleUse: @unchecked Sendable {
    // @unchecked Sendable: `claimed` is only read or written under `lock`.
    private let lock = NSLock()
    private var claimed = false

    var isClaimed: Bool { lock.withLock { claimed } }

    func claim() -> Bool {
        lock.withLock {
            defer { claimed = true }
            return !claimed
        }
    }
}
