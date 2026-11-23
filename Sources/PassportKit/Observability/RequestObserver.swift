/// Receives diagnostic events about requests to the authorization server (specification §12).
///
/// Events carry no URLs with query strings, no bodies and no secrets. Implementations must be fast and must
/// not throw; they are called inline on the requesting task.
public protocol RequestObserver: Sendable {
    /// Records one event.
    func record(_ event: RequestEvent)
}

/// A request to a server, its response, or its failure to get one.
///
/// Cases may be added in a minor release: the enumeration is not frozen, so a `switch` over it needs a `default`.
public enum RequestEvent: Sendable, Equatable {
    /// A request is about to be sent. `grantType` is set for token endpoint requests.
    case request(endpoint: Endpoint, grantType: GrantType?)
    /// A response arrived. `errorCode` is the OAuth `error` member of a non-2xx response when it is a plain token
    /// of at most 64 characters. It is passed on as the server sent it, because RFC 6749 §5.2 limits the member to
    /// an error code. `duration` is measured with the client's injected clock.
    case response(endpoint: Endpoint, statusCode: Int, errorCode: String?, duration: Duration)
    /// A request ended without an HTTP response: no connection, TLS failure, timeout, or task cancellation.
    /// Every ``request(endpoint:grantType:)`` is followed by exactly one
    /// ``response(endpoint:statusCode:errorCode:duration:)`` or one ``transportFailure(endpoint:grantType:duration:)``.
    /// `duration` is measured with the client's injected clock.
    case transportFailure(endpoint: Endpoint, grantType: GrantType?, duration: Duration)
}

extension RequestEvent {
    /// Which endpoint of the authorization server a request targets. An open set: new endpoints can be added
    /// without breaking source compatibility.
    public struct Endpoint: RawRepresentable, Sendable, Hashable {
        /// A short, stable name of the endpoint.
        public let rawValue: String

        /// Creates an endpoint from its name.
        public init(rawValue: String) {
            self.rawValue = rawValue
        }

        /// The token endpoint (RFC 6749 §3.2).
        public static let token = Endpoint(rawValue: "token")
        /// The device authorization endpoint (RFC 8628 §3.1).
        public static let deviceAuthorization = Endpoint(rawValue: "deviceAuthorization")
        /// The revocation endpoint (RFC 7009 §2).
        public static let revocation = Endpoint(rawValue: "revocation")
        /// The authorization server metadata endpoint (RFC 8414 §3).
        public static let metadata = Endpoint(rawValue: "metadata")
    }
}
