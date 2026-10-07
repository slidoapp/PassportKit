/// A source of cryptographically secure random bytes, injected so `state` and PKCE verifiers are testable.
public protocol RandomSource: Sendable {
    /// Returns `count` random bytes.
    func bytes(count: Int) -> [UInt8]
}
