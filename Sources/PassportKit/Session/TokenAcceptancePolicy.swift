/// The verdict of a ``TokenAcceptancePolicy``.
public enum TokenAcceptance: Sendable {
    /// The token may be cached and used.
    case accept
    /// The token is useless for its target. `reason` appears in the error, so it must not contain secrets.
    case reject(reason: String)
}

/// What a ``TokenAcceptancePolicy`` is asked to judge. A struct, so that members can be added without breaking
/// existing policies.
public struct TokenAcceptanceContext: Sendable {
    /// The issued token, with its granted scope.
    public var token: AccessToken
    /// The token endpoint response the token was built from.
    public var response: TokenResponse

    /// The target the token was issued for.
    public var target: TokenTarget { token.target }

    package init(token: AccessToken, response: TokenResponse) {
        self.token = token
        self.response = response
    }
}

/// Decides whether an issued access token is good enough to become current (ADR 0004).
///
/// An HTTP 200 is not proof of access: a server may narrow the scope and still answer 200 (RFC 6749 §3.3).
/// The policy runs on every token ``TokenManager`` issues, before the token is cached or returned.
public protocol TokenAcceptancePolicy: Sendable {
    /// Judges the token in `context`. Must not call back into the manager that is evaluating it.
    func evaluate(_ context: TokenAcceptanceContext) async -> TokenAcceptance
}

/// Accepts every token. The default policy of ``TokenManager``, which therefore does not check scope.
public struct AcceptAnyToken: TokenAcceptancePolicy {
    /// Creates the policy.
    public init() {}

    /// Always ``TokenAcceptance/accept``.
    public func evaluate(_ context: TokenAcceptanceContext) async -> TokenAcceptance { .accept }
}

/// Chooses the targets a policy applies to. An open set: new selectors can be added without breaking source
/// compatibility.
public struct TargetSelector: Sendable {
    private let selects: @Sendable (TokenTarget) -> Bool

    /// Every target.
    public static let all = TargetSelector { _ in true }
    /// Targets that name at least one resource indicator (RFC 8707), where servers are seen to narrow the scope.
    public static let withResources = TargetSelector { !$0.resources.isEmpty }

    /// The targets for which `predicate` is true.
    public static func matching(_ predicate: @escaping @Sendable (TokenTarget) -> Bool) -> TargetSelector {
        TargetSelector(predicate)
    }

    private init(_ selects: @escaping @Sendable (TokenTarget) -> Bool) {
        self.selects = selects
    }

    /// Whether `target` is selected.
    public func isSelected(_ target: TokenTarget) -> Bool { selects(target) }
}

/// Accepts a token for a selected target only if at least one of the given scopes was granted.
///
/// By default the policy applies to targets with resources, where servers are seen to answer 200 with a
/// narrowed scope when the user cannot access the resource. A token whose granted scope is unknown is rejected.
public struct RequireAnyScope: TokenAcceptancePolicy {
    private let scopes: ScopeSet
    private let targets: TargetSelector

    /// Creates the policy. Tokens of targets that `targets` does not select are always accepted.
    public init(_ scopes: ScopeSet, forTargets targets: TargetSelector = .withResources) {
        self.scopes = scopes
        self.targets = targets
    }

    /// Rejects a selected target's token that carries none of the required scopes.
    public func evaluate(_ context: TokenAcceptanceContext) async -> TokenAcceptance {
        guard targets.isSelected(context.target) else { return .accept }
        guard let granted = context.token.grantedScope else { return .reject(reason: "The granted scope is unknown.") }
        return scopes.scopes.isDisjoint(with: granted.scopes)
            ? .reject(reason: "None of the required scopes was granted.") : .accept
    }
}

/// A policy that runs a closure, for rules that need no type of their own.
public struct ClosureTokenAcceptancePolicy: TokenAcceptancePolicy {
    private let body: @Sendable (TokenAcceptanceContext) async -> TokenAcceptance

    /// Creates a policy that returns what `body` returns.
    public init(_ body: @escaping @Sendable (TokenAcceptanceContext) async -> TokenAcceptance) {
        self.body = body
    }

    /// Runs the closure.
    public func evaluate(_ context: TokenAcceptanceContext) async -> TokenAcceptance { await body(context) }
}

extension TokenAcceptancePolicy where Self == ClosureTokenAcceptancePolicy {
    /// A policy that runs `body`: `acceptancePolicy: .custom { context in ... }`.
    public static func custom(
        _ body: @escaping @Sendable (TokenAcceptanceContext) async -> TokenAcceptance
    ) -> ClosureTokenAcceptancePolicy {
        ClosureTokenAcceptancePolicy(body)
    }
}
