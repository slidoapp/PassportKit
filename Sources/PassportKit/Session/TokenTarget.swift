import Foundation

/// What an access token is for: the key under which `TokenManager` caches and coalesces tokens.
///
/// Two targets are equal when their method, scope, set of `resources` and set of `audiences` are equal: the
/// order and repetition of resources and audiences do not matter, because they name a set (RFC 8707 §2.1,
/// RFC 8693 §2.1). A target without a `scope` and one with an empty scope are different: the first asks the
/// server for its default, the second for nothing. A token is never handed to a caller that asked for another
/// target (RFC 8707 §2).
///
/// The token of a target keeps the order of the first caller that asked for it.
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

extension TokenTarget {
    /// What equality and hashing look at: the members with `resources` and `audiences` as sorted sets.
    private struct Identity: Hashable {
        var method: Method
        var resources: [String]
        var audiences: [String]
        var scope: ScopeSet?
    }

    private var identity: Identity {
        Identity(
            method: method, resources: Set(resources.map(\.absoluteString)).sorted(),
            audiences: Set(audiences).sorted(), scope: scope)
    }

    /// Whether both targets ask for the same token; see the type's description.
    public static func == (lhs: TokenTarget, rhs: TokenTarget) -> Bool { lhs.identity == rhs.identity }

    /// Hashes what ``==(_:_:)`` compares.
    public func hash(into hasher: inout Hasher) { hasher.combine(identity) }
}
