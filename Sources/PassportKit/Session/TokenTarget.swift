import Foundation

/// What an access token is for: the key under which `TokenManager` caches and coalesces tokens.
///
/// Two targets are equal only when every member is equal, including the order of `resources` and
/// `audiences`, and a token is never handed to a caller that asked for another target (RFC 8707 §2).
public struct TokenTarget: Sendable, Hashable {
    /// How a token for the target is obtained.
    public enum Method: Sendable, Hashable {
        /// A refresh grant with `resources` and `scope` (RFC 6749 §6, RFC 8707 §2.2).
        case refreshGrant
        /// A token exchange of the default access token (RFC 8693 §2.1) for one bound to `resources` and `audiences`.
        case exchangeAccessToken
    }

    /// How the token is obtained.
    public var method: Method
    /// Resource indicators the token is bound to (RFC 8707).
    public var resources: [URL]
    /// Logical target services (RFC 8693 §2.1). Only meaningful for ``Method/exchangeAccessToken``.
    public var audiences: [String]
    /// The scope requested for the token.
    public var scope: ScopeSet?

    /// Creates a target.
    public init(
        method: Method = .refreshGrant,
        resources: [URL] = [],
        audiences: [String] = [],
        scope: ScopeSet? = nil
    ) {
        self.method = method
        self.resources = resources
        self.audiences = audiences
        self.scope = scope
    }

    /// The token of the root grant: a refresh grant without resources or scope.
    public static let `default` = TokenTarget()
}
