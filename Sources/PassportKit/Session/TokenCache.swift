import Foundation

/// Cached access tokens per target, and the counter that gives each cached token its generation.
struct TokenCache {
    private var tokens: [TokenTarget: AccessToken] = [:]
    private var lastGeneration = 0

    /// A new generation, unique for the life of the manager, so a token from a cleared session never matches.
    mutating func nextGeneration() -> Int {
        lastGeneration += 1
        return lastGeneration
    }

    /// The cached token when it is still usable `minimumLifetime` from `now`.
    func usableToken(for target: TokenTarget, now: Date, minimumLifetime: TimeInterval) -> AccessToken? {
        guard let token = tokens[target], let expiresAt = token.expiresAt,
            expiresAt.timeIntervalSince(now) > minimumLifetime
        else { return nil }
        return token
    }

    mutating func store(_ token: AccessToken) {
        tokens[token.target] = token
    }

    /// Drops the token of `target` only when it is still the one with `generation`.
    mutating func remove(target: TokenTarget, generation: Int) {
        if tokens[target]?.generation == generation { tokens[target] = nil }
    }

    mutating func removeAll() {
        tokens = [:]
    }
}

extension Duration {
    /// The duration in seconds.
    var seconds: TimeInterval {
        Double(components.seconds) + Double(components.attoseconds) / 1e18
    }
}
