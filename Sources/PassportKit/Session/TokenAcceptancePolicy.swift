/// The verdict of a ``TokenAcceptancePolicy``.
public enum TokenAcceptance: Sendable {
    /// The token may be cached and used.
    case accept
    /// The token is useless for its target. `reason` appears in the error, so it must not contain secrets.
    case reject(reason: String)
}

/// Decides whether an issued access token is good enough to become current (ADR 0004).
///
/// An HTTP 200 is not proof of access: a server may narrow the scope and still answer 200 (RFC 6749 §3.3).
/// The policy runs on every token `TokenManager` issues, before the token is cached or returned.
public protocol TokenAcceptancePolicy: Sendable {
    /// Judges `token`, issued from `response`. Must not call back into the manager that is evaluating it.
    func evaluate(_ token: AccessToken, response: TokenResponse) async -> TokenAcceptance
}

/// Accepts every token. The default policy.
public struct AcceptAnyToken: TokenAcceptancePolicy {
    /// Creates the policy.
    public init() {}

    /// Always ``TokenAcceptance/accept``.
    public func evaluate(_ token: AccessToken, response: TokenResponse) async -> TokenAcceptance { .accept }
}

/// Accepts a token for a selected target only if at least one of the given scopes was granted.
///
/// By default the policy applies to targets with resources, where servers are seen to answer 200 with a
/// narrowed scope when the user cannot access the resource. A token whose granted scope is unknown is rejected.
public struct RequireAnyScope: TokenAcceptancePolicy {
    private let scopes: ScopeSet
    private let appliesTo: @Sendable (TokenTarget) -> Bool

    /// Creates the policy. Targets for which `predicate` is false are always accepted.
    public init(
        _ scopes: ScopeSet, when predicate: @escaping @Sendable (TokenTarget) -> Bool = { !$0.resources.isEmpty }
    ) {
        self.scopes = scopes
        self.appliesTo = predicate
    }

    /// Rejects a selected target's token that carries none of the required scopes.
    public func evaluate(_ token: AccessToken, response: TokenResponse) async -> TokenAcceptance {
        guard appliesTo(token.target) else { return .accept }
        guard let granted = token.grantedScope else { return .reject(reason: "The granted scope is unknown.") }
        return scopes.scopes.isDisjoint(with: granted.scopes)
            ? .reject(reason: "None of the required scopes was granted.") : .accept
    }
}
