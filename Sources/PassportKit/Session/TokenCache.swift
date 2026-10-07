import Foundation

/// Cached access tokens per target, the recent rejections per target, and the counter that gives each cached
/// token its generation.
///
/// Targets can come from untrusted input (a resource URL per request), so both tables are bounded: every
/// insertion drops what has expired and then the oldest entries beyond ``capacity``.
struct TokenCache {
    static let capacity = 256

    private var tokens: [TokenTarget: AccessToken] = [:]
    private var rejections: [TokenTarget: (error: PassportError, until: Date)] = [:]
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

    var tokenCount: Int { tokens.count }
    var rejectionCount: Int { rejections.count }

    mutating func store(_ token: AccessToken, now: Date) {
        tokens[token.target] = token
        prune(now: now)
    }

    /// Drops the token of `target` only when it is still the one with `generation`.
    mutating func remove(target: TokenTarget, generation: Int) {
        if tokens[target]?.generation == generation { tokens[target] = nil }
    }

    mutating func removeAll() {
        tokens = [:]
        rejections = [:]
    }

    /// Remembers that the token of `target` was rejected, until `until`.
    mutating func reject(target: TokenTarget, error: PassportError, until: Date, now: Date) {
        rejections[target] = (error, until)
        prune(now: now)
    }

    /// Drops expired entries, then the oldest ones (lowest generation, earliest end) beyond the capacity.
    private mutating func prune(now: Date) {
        tokens = tokens.filter { $0.value.expiresAt.map { $0 > now } ?? true }
        rejections = rejections.filter { now < $0.value.until }
        while tokens.count > Self.capacity, let oldest = tokens.min(by: { $0.value.generation < $1.value.generation }) {
            tokens[oldest.key] = nil
        }
        while rejections.count > Self.capacity, let oldest = rejections.min(by: { $0.value.until < $1.value.until }) {
            rejections[oldest.key] = nil
        }
    }

    /// The rejection of `target` that is still remembered at `now`.
    func rejection(for target: TokenTarget, now: Date) -> PassportError? {
        guard let rejection = rejections[target], now < rejection.until else { return nil }
        return rejection.error
    }

    mutating func forgetRejection(of target: TokenTarget) {
        rejections[target] = nil
    }
}

extension Duration {
    /// The duration in seconds.
    var seconds: TimeInterval {
        Double(components.seconds) + Double(components.attoseconds) / 1e18
    }
}
