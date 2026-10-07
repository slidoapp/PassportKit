import Foundation

/// A ``WallClock`` backed by the system clock.
public struct SystemWallClock: WallClock {
    /// Creates a system clock.
    public init() {}

    /// The current system date.
    public func now() -> Date {
        Date()
    }
}
