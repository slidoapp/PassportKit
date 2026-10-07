/// Receives diagnostic events about authorization server requests (specification §12).
///
/// Events carry no URLs with query strings, no bodies and no secrets. Implementations must be fast and must
/// not throw; they are called inline on the requesting task.
public protocol PassportObserver: Sendable {
    /// Records one event.
    func record(_ event: PassportEvent)
}

/// Something that happened while talking to a server.
public enum PassportEvent: Sendable, Equatable {
    /// A request is about to be sent. `grantType` is set for token endpoint requests.
    case request(endpoint: EndpointKind, grantType: GrantType?)
    /// A response arrived. `errorCode` is the OAuth `error` member of a non-2xx response when it is a plain token.
    /// `duration` is measured with the client's injected clock.
    case response(endpoint: EndpointKind, statusCode: Int, errorCode: String?, duration: Duration)
    /// A request ended without an HTTP response: no connection, TLS failure, timeout, or task cancellation.
    /// Every ``request(endpoint:grantType:)`` is followed by exactly one ``response(endpoint:statusCode:errorCode:duration:)``
    /// or one ``transportFailure(endpoint:grantType:duration:)``. `duration` is measured with the client's injected clock.
    case transportFailure(endpoint: EndpointKind, grantType: GrantType?, duration: Duration)
}

/// Which kind of server endpoint a request targets.
public enum EndpointKind: String, Sendable {
    /// The token endpoint (RFC 6749 §3.2).
    case token
    /// The device authorization endpoint (RFC 8628 §3.1).
    case deviceAuthorization
    /// The revocation endpoint (RFC 7009 §2).
    case revocation
    /// The authorization server metadata endpoint (RFC 8414 §3).
    case metadata
    /// A protected resource.
    case resource
}
