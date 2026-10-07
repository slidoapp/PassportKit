import Foundation
import PassportKit

/// A ``WallClock`` that returns a settable date and never moves on its own.
public final class FixedWallClock: WallClock, @unchecked Sendable {
    // @unchecked Sendable: the date is only read and written under `lock`.
    private let lock = NSLock()
    private var date: Date

    /// Creates a clock stopped at `date` (default: 2023-11-14T22:13:20Z).
    public init(_ date: Date = Date(timeIntervalSince1970: 1_700_000_000)) { self.date = date }

    public func now() -> Date { lock.withLock { date } }

    /// Stops the clock at `date`.
    public func set(_ date: Date) { lock.withLock { self.date = date } }

    /// Moves the clock by `duration` (negative values move it back).
    public func advance(by duration: Duration) {
        let seconds = Double(duration.components.seconds) + Double(duration.components.attoseconds) / 1e18
        lock.withLock { date = date.addingTimeInterval(seconds) }
    }
}

/// A ``RandomSource`` that returns a fixed byte pattern, repeated as often as needed.
public final class SequenceRandomSource: RandomSource, @unchecked Sendable {
    // @unchecked Sendable: the read position is only touched under `lock`.
    private let lock = NSLock()
    private let pattern: [UInt8]
    private var position = 0

    /// Creates a source that cycles through `pattern` (default: 0, 1, ... 255). The pattern must not be empty.
    public init(_ pattern: [UInt8] = Array(0...255)) {
        precondition(!pattern.isEmpty, "A random pattern needs at least one byte.")
        self.pattern = pattern
    }

    public func bytes(count: Int) -> [UInt8] {
        lock.withLock {
            (0..<count).map { _ in
                defer { position = (position + 1) % pattern.count }
                return pattern[position]
            }
        }
    }
}
