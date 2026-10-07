/// A ``RandomSource`` backed by `SystemRandomNumberGenerator`, a CSPRNG on every supported platform.
public struct SystemRandomSource: RandomSource {
    /// Creates a system random source.
    public init() {}

    /// Returns `count` random bytes.
    public func bytes(count: Int) -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<max(count, 0)).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    }
}
