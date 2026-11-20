import Foundation

/// What an access token is for: the key under which `OAuthSession` caches and coalesces tokens.
///
/// Two targets are equal when their derivation, scope, set of `resources` and set of `audiences` are equal: the
/// order and repetition of resources and audiences do not matter, because they name a set (RFC 8707 §2.1,
/// RFC 8693 §2.1). A target without a `scope` and one with an empty scope are different: the first asks the
/// server for its default, the second for nothing. A token is never handed to a caller that asked for another
/// target (RFC 8707 §2).
///
/// The token of a target keeps the order of the first caller that asked for it.
public struct TokenTarget: Sendable, Hashable {
    /// How a token for the target is obtained. An open set: new derivations can be added without breaking
    /// source compatibility.
    public struct Derivation: Sendable, Hashable {
        private enum Storage: Sendable, Hashable {
            case refreshGrant
            case tokenExchange
        }

        private let storage: Storage

        /// A refresh grant with `resources` and `scope` (RFC 6749 §6, RFC 8707 §2.2).
        public static let refreshGrant = Derivation(storage: .refreshGrant)
        /// A token exchange of the default access token (RFC 8693 §2.1) for one bound to `resources` and `audiences`.
        public static let tokenExchange = Derivation(storage: .tokenExchange)
    }

    /// How the token is obtained.
    public var derivation: Derivation
    /// Resource indicators the token is bound to (RFC 8707).
    public var resources: [URL]
    /// Logical target services, sent as `audience` in a token exchange (RFC 8693 §2.1).
    ///
    /// Only a ``Derivation/tokenExchange`` target may name audiences: ``OAuthSession/accessToken(for:)`` throws
    /// ``PassportError/Code-swift.struct/invalidConfiguration`` for a ``Derivation/refreshGrant`` target with
    /// audiences.
    public var audiences: [String]
    /// The scope requested for the token.
    public var scope: ScopeSet?

    package init(
        derivation: Derivation,
        resources: [URL] = [],
        audiences: [String] = [],
        scope: ScopeSet? = nil
    ) {
        self.derivation = derivation
        self.resources = resources
        self.audiences = audiences
        self.scope = scope
    }

    /// The token of the root grant: a refresh grant without resources or scope.
    public static let `default` = TokenTarget(derivation: .refreshGrant)

    /// A token obtained with a refresh grant that names `resources` and `scope` (RFC 6749 §6, RFC 8707 §2.2).
    public static func refreshGrant(resources: [URL] = [], scope: ScopeSet? = nil) -> TokenTarget {
        TokenTarget(derivation: .refreshGrant, resources: resources, scope: scope)
    }

    /// A token obtained by exchanging the default access token for one bound to `resources` and `audiences`
    /// (RFC 8693 §2.1).
    public static func tokenExchange(
        resources: [URL] = [],
        audiences: [String] = [],
        scope: ScopeSet? = nil
    ) -> TokenTarget {
        TokenTarget(derivation: .tokenExchange, resources: resources, audiences: audiences, scope: scope)
    }
}

extension TokenTarget {
    /// What equality and hashing look at: the members with `resources` and `audiences` as sorted sets.
    private struct Identity: Hashable {
        var derivation: Derivation
        var resources: [String]
        var audiences: [String]
        var scope: ScopeSet?
    }

    private var identity: Identity {
        Identity(
            derivation: derivation, resources: Set(resources.map(\.absoluteString)).sorted(),
            audiences: Set(audiences).sorted(), scope: scope)
    }

    /// Whether both targets ask for the same token; see the type's description.
    public static func == (lhs: TokenTarget, rhs: TokenTarget) -> Bool { lhs.identity == rhs.identity }

    /// Hashes what ``==(_:_:)`` compares.
    public func hash(into hasher: inout Hasher) { hasher.combine(identity) }
}

extension TokenTarget {
    /// Chooses the targets a policy applies to, such as those of ``RequireAnyScope``. An open set: new selectors can be
    /// added without breaking source compatibility.
    public struct Selector: Sendable {
        private let selects: @Sendable (TokenTarget) -> Bool

        /// Every target.
        public static let all = Selector { _ in true }
        /// Targets that name at least one resource indicator (RFC 8707), where servers are seen to narrow the scope.
        public static let withResources = Selector { !$0.resources.isEmpty }

        /// The targets for which `predicate` is true.
        public static func matching(_ predicate: @escaping @Sendable (TokenTarget) -> Bool) -> Selector {
            Selector(predicate)
        }

        private init(_ selects: @escaping @Sendable (TokenTarget) -> Bool) {
            self.selects = selects
        }

        /// Whether `target` is selected.
        public func isSelected(_ target: TokenTarget) -> Bool { selects(target) }
    }
}
