import Foundation

/// Test-only clock whose `sleep` suspends until the test advances time.
///
/// Tests drive it with `advance(by:)` or, to avoid racing the code under test, with
/// `advanceToNextSleeper()` which first waits until a sleeper has registered.
final class ManualClock: Clock, @unchecked Sendable {
    // @unchecked Sendable: all mutable state is guarded by `lock`; continuations are resumed outside it.

    struct Instant: InstantProtocol {
        var offset: Duration
        func advanced(by duration: Duration) -> Instant { Instant(offset: offset + duration) }
        func duration(to other: Instant) -> Duration { other.offset - offset }
        static func < (lhs: Instant, rhs: Instant) -> Bool { lhs.offset < rhs.offset }
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
    private var arrivalWaiters: [CheckedContinuation<Void, Never>] = []

    var now: Instant { lock.withLock { current } }
    var minimumResolution: Duration { .nanoseconds(1) }

    /// The number of tasks currently suspended in `sleep`.
    var sleeperCount: Int { lock.withLock { sleepers.count } }

    func sleep(until deadline: Instant, tolerance: Duration?) async throws {
        let id = lock.withLock {
            nextID += 1
            return nextID
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                enum Outcome {
                    case wake
                    case cancel
                    case parked([CheckedContinuation<Void, Never>])
                }
                let outcome = lock.withLock { () -> Outcome in
                    if cancelled.remove(id) != nil { return .cancel }
                    if deadline <= current { return .wake }
                    sleepers.append(Sleeper(id: id, deadline: deadline, continuation: continuation))
                    defer { arrivalWaiters = [] }
                    return .parked(arrivalWaiters)
                }
                switch outcome {
                case .wake: continuation.resume()
                case .cancel: continuation.resume(throwing: CancellationError())
                case .parked(let waiters): for waiter in waiters { waiter.resume() }
                }
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

    /// Moves time forward and wakes every sleeper whose deadline has been reached.
    func advance(by duration: Duration) {
        let due = lock.withLock { () -> [Sleeper] in
            current = current.advanced(by: duration)
            let due = sleepers.filter { $0.deadline <= current }
            sleepers.removeAll { $0.deadline <= current }
            return due
        }
        for sleeper in due { sleeper.continuation.resume() }
    }

    /// Suspends until at least one task is sleeping.
    func waitForSleeper() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            let ready = lock.withLock { () -> Bool in
                if !sleepers.isEmpty { return true }
                arrivalWaiters.append(continuation)
                return false
            }
            if ready { continuation.resume() }
        }
    }

    /// Waits for a sleeper, then advances exactly to the earliest deadline. Returns how long that was.
    @discardableResult
    func advanceToNextSleeper() async -> Duration {
        await waitForSleeper()
        let step = lock.withLock { () -> Duration in
            let earliest = sleepers.map(\.deadline).min() ?? current
            return max(.zero, current.duration(to: earliest))
        }
        advance(by: step)
        return step
    }
}
