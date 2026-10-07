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

    /// Checks that every endpoint uses `https`, or `http` with a loopback host (RFC 6749 §3.1, §3.2, RFC 8252 §8.3).
    ///
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/invalidConfiguration`` otherwise.
    func validate() throws {
        for (name, url) in [
            ("authorization", authorization), ("token", token), ("deviceAuthorization", deviceAuthorization),
            ("revocation", revocation),
        ] {
            guard let url else { continue }
            try Self.validateSecureTransport(of: url, name: "\(name) endpoint")
        }
    }

    static func validateSecureTransport(of url: URL, name: String) throws {
        let scheme = url.scheme?.lowercased()
        let isAllowed = scheme == "https" || (scheme == "http" && LoopbackHost.isLoopback(url.host))
        guard isAllowed, url.host?.isEmpty == false else {
            throw PassportError(
                .invalidConfiguration,
                detail: "The \(name) must use https, or http on a loopback host."
            )
        }
    }
}
