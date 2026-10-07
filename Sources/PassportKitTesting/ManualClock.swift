import Foundation

/// A clock whose `sleep` suspends until a test advances time, so tests never sleep for real.
///
/// Drive it with ``advance(by:)`` or, to avoid racing the code under test, with
/// ``advanceToNextSleeper()`` which first waits until a task is sleeping. Sleeping honours task
/// cancellation (it throws `CancellationError`) and sleepers wake in deadline order.
public final class ManualClock: Clock, @unchecked Sendable {
    // @unchecked Sendable: all mutable state is guarded by `lock`; continuations are resumed outside it.

    /// A point on the manual timeline, measured from the clock's creation.
    public struct Instant: InstantProtocol {
        /// The distance from the clock's origin.
        public var offset: Duration

        /// Creates an instant `offset` after the origin.
        public init(offset: Duration) { self.offset = offset }

        public func advanced(by duration: Duration) -> Instant { Instant(offset: offset + duration) }
        public func duration(to other: Instant) -> Duration { other.offset - offset }
        public static func < (lhs: Instant, rhs: Instant) -> Bool { lhs.offset < rhs.offset }
    }

    private struct Sleeper {
        let id: Int
        let deadline: Instant
        let continuation: CheckedContinuation<Void, any Error>
    }

    private let lock = NSLock()
    private var current = Instant(offset: .zero)
    private var sleepers: [Sleeper] = []
    private var cancelled: Set<Int> = []
    private var nextID = 0

    /// Creates a clock at its origin.
    public init() {}

    public var now: Instant { lock.withLock { current } }
    public var minimumResolution: Duration { .nanoseconds(1) }

    /// The number of tasks currently suspended in `sleep`.
    public var sleeperCount: Int { lock.withLock { sleepers.count } }

    public func sleep(until deadline: Instant, tolerance: Duration?) async throws {
        let id = lock.withLock {
            nextID += 1
            return nextID
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let outcome = lock.withLock { () -> Result<Void, CancellationError>? in
                    if cancelled.remove(id) != nil { return .failure(CancellationError()) }
                    if deadline <= current { return .success(()) }
                    sleepers.append(Sleeper(id: id, deadline: deadline, continuation: continuation))
                    return nil
                }
                if let outcome { continuation.resume(with: outcome.mapError { $0 as any Error }) }
            }
        } onCancel: {
            let sleeper = lock.withLock { () -> Sleeper? in
                guard let index = sleepers.firstIndex(where: { $0.id == id }) else {
                    cancelled.insert(id)
                    return nil
                }
                return sleepers.remove(at: index)
            }
            sleeper?.continuation.resume(throwing: CancellationError())
        }
    }

    /// Moves time forward and wakes every sleeper whose deadline has been reached, earliest first.
    ///
    /// A negative `duration` is ignored: the clock never runs backwards.
    public func advance(by duration: Duration) {
        let due = lock.withLock { () -> [Sleeper] in
            current = current.advanced(by: max(.zero, duration))
            let due = sleepers.filter { $0.deadline <= current }.sorted { $0.deadline < $1.deadline }
            sleepers.removeAll { $0.deadline <= current }
            return due
        }
        for sleeper in due { sleeper.continuation.resume() }
    }

    /// Suspends until at least one task is sleeping, or the calling task is cancelled.
    public func waitForSleeper() async {
        while sleeperCount == 0 && !Task.isCancelled { await Task.yield() }
    }

    /// Waits for a sleeper, then advances exactly to the earliest deadline. Returns how long that was.
    @discardableResult
    public func advanceToNextSleeper() async -> Duration {
        await waitForSleeper()
        let step = lock.withLock { () -> Duration in
            guard let earliest = sleepers.map(\.deadline).min() else { return .zero }
            return max(.zero, current.duration(to: earliest))
        }
        advance(by: step)
        return step
    }
}
