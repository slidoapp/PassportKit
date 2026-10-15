import Foundation

/// The authorization server endpoints a client talks to.
public struct Endpoints: Sendable, Hashable {
    /// The authorization endpoint (RFC 6749 §3.1); required for the authorization code grant.
    public var authorization: URL?
    /// The token endpoint (RFC 6749 §3.2).
    public var token: URL
    /// The device authorization endpoint (RFC 8628 §3.1).
    public var deviceAuthorization: URL?
    /// The revocation endpoint (RFC 7009 §2).
    public var revocation: URL?

    /// Creates endpoints. ``OAuthClient`` validates them when it is created.
    public init(authorization: URL? = nil, token: URL, deviceAuthorization: URL? = nil, revocation: URL? = nil) {
        self.authorization = authorization
        self.token = token
        self.deviceAuthorization = deviceAuthorization
        self.revocation = revocation
    }

    /// Checks that every endpoint uses `https` (RFC 6749 §3.1, §3.2), or `http` with a loopback host when
    /// `allowsInsecureLoopback` is set.
    ///
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/invalidConfiguration`` otherwise.
    func validate(allowsInsecureLoopback: Bool = false) throws {
        for (name, url) in [
            ("authorization", authorization), ("token", token), ("deviceAuthorization", deviceAuthorization),
            ("revocation", revocation),
        ] {
            guard let url else { continue }
            try Self.validateSecureTransport(
                of: url, name: "\(name) endpoint", allowsInsecureLoopback: allowsInsecureLoopback)
        }
    }

    /// Words, not the property name: descriptions redact runs of 24 or more characters.
    static let optInHint =
        "Opt in to insecure loopback endpoints in the client configuration to allow http on a loopback host."

    static func validateSecureTransport(of url: URL, name: String, allowsInsecureLoopback: Bool) throws {
        let scheme = url.scheme?.lowercased()
        let isAllowed =
            scheme == "https" || (scheme == "http" && allowsInsecureLoopback && LoopbackHost.isLoopback(url.host))
        guard isAllowed, url.host?.isEmpty == false else {
            throw PassportError(
                .invalidConfiguration,
                detail: allowsInsecureLoopback
                    ? "The \(name) must use https, or http on a loopback host."
                    : "The \(name) must use https. \(Self.optInHint)"
            )
        }
    }
}
