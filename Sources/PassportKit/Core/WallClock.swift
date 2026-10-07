import Foundation

/// A source of calendar time, injected so token expiry is testable.
public protocol WallClock: Sendable {
    /// The current date.
    func now() -> Date
}
