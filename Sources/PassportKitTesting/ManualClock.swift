import Foundation
import os

/// A clock whose `sleep` suspends until a test advances time, so tests never sleep for real.
///
/// Drive it with ``advance(by:)`` or, to avoid racing the code under test, with
/// ``advanceToNextSleeper()`` which first waits until a task is sleeping. Sleeping honours task
/// cancellation (it throws `CancellationError`) and sleepers wake in deadline order. Waiting for a sleeper
/// is bounded by real time and ends in ``WaitTimeout`` when none arrives, so a test that never reaches
/// `sleep` fails on its own instead of stopping the test process.
public final class ManualClock: Clock, Sendable {
    /// A point on the manual timeline, measured from the clock's creation.
    public struct Instant: InstantProtocol, Sendable {
        /// The distance from the clock's origin.
        public var offset: Duration

        /// Creates an instant `offset` after the origin.
        public init(offset: Duration) { self.offset = offset }

        public func advanced(by duration: Duration) -> Instant { Instant(offset: offset + duration) }
        public func duration(to other: Instant) -> Duration { other.offset - offset }
        public static func < (lhs: Instant, rhs: Instant) -> Bool { lhs.offset < rhs.offset }
    }

    /// Thrown by ``waitForSleeper()`` and ``advanceToNextSleeper()`` when no task slept within the real-time
    /// bound: the code under test never reached `sleep`, or the machine was too slow to get there.
    public struct WaitTimeout: Error, Sendable, CustomStringConvertible {
        /// The real time that was waited.
        public let timeout: Duration

        public var description: String {
            "ManualClock: no task slept within \(timeout) of real time."
        }
    }

    /// The real-time bound of ``waitForSleeper()`` and ``advanceToNextSleeper()``. Generous on purpose: a
    /// loaded CI machine can delay a wake-up by seconds, and a timeout is only a failure, never a hang.
    static let defaultWaitTimeout = Duration.seconds(60)

    private struct Waiter {
        let id: Int
        let continuation: CheckedContinuation<Void, Never>
    }

    private struct Sleeper {
        let id: Int
        let deadline: Instant
        let continuation: CheckedContinuation<Void, any Error>
    }

    private struct State {
        var current = Instant(offset: .zero)
        var sleepers: [Sleeper] = []
        var cancelled: Set<Int> = []
        var waiters: [Waiter] = []
        var cancelledWaiters: Set<Int> = []
        var nextID = 0
    }

    // Continuations are resumed outside the lock.
    private let state = OSAllocatedUnfairLock(initialState: State())

    /// Creates a clock at its origin.
    public init() {}

    public var now: Instant { state.withLock { $0.current } }
    public var minimumResolution: Duration { .nanoseconds(1) }

    /// The number of tasks currently suspended in `sleep`.
    public var sleeperCount: Int { state.withLock { $0.sleepers.count } }

    public func sleep(until deadline: Instant, tolerance: Duration?) async throws {
        let id = state.withLock { state in
            state.nextID += 1
            return state.nextID
        }
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, any Error>) in
                let (outcome, waiters) = state.withLock { state -> (Result<Void, CancellationError>?, [Waiter]) in
                    if state.cancelled.remove(id) != nil { return (.failure(CancellationError()), []) }
                    if deadline <= state.current { return (.success(()), []) }
                    state.sleepers.append(Sleeper(id: id, deadline: deadline, continuation: continuation))
                    defer { state.waiters.removeAll() }
                    return (nil, state.waiters)
                }
                if let outcome { continuation.resume(with: outcome.mapError { $0 as any Error }) }
                for waiter in waiters { waiter.continuation.resume() }
            }
        } onCancel: {
            let sleeper = state.withLock { state -> Sleeper? in
                guard let index = state.sleepers.firstIndex(where: { $0.id == id }) else {
                    state.cancelled.insert(id)
                    return nil
                }
                return state.sleepers.remove(at: index)
            }
            sleeper?.continuation.resume(throwing: CancellationError())
        }
    }

    /// Moves time forward and wakes every sleeper whose deadline has been reached, earliest first.
    ///
    /// A negative `duration` is ignored: the clock never runs backwards.
    public func advance(by duration: Duration) {
        let due = state.withLock { state -> [Sleeper] in
            state.current = state.current.advanced(by: max(.zero, duration))
            let now = state.current
            let due = state.sleepers.filter { $0.deadline <= now }.sorted { $0.deadline < $1.deadline }
            state.sleepers.removeAll { $0.deadline <= now }
            return due
        }
        for sleeper in due { sleeper.continuation.resume() }
    }

    /// Waits until at least one task is sleeping, the calling task is cancelled, or `timeout` of real time passes.
    ///
    /// Returns whether a task is sleeping. The wait is resumed by the sleeper itself, not polled, so it costs
    /// nothing while the code under test is working; a code path that never reaches `sleep` ends the wait after
    /// `timeout` instead of hanging.
    public func waitForSleeper(timeout: Duration) async -> Bool {
        if sleeperCount > 0 { return true }
        return await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.untilSleeperRegisters() }
            group.addTask { try? await ContinuousClock().sleep(for: timeout) }
            // Whichever ends first (a sleeper, the timeout, or cancellation of the caller) ends the other.
            await group.next()
            group.cancelAll()
            return sleeperCount > 0
        }
    }

    /// Suspends until at least one task is sleeping or the calling task is cancelled.
    ///
    /// Throws ``WaitTimeout`` when no task slept within 60 seconds of real time: the code under test never
    /// reached `sleep`, and waiting longer would only hang the test. The error fails the calling test and
    /// nothing else. Use ``waitForSleeper(timeout:)`` to choose the bound or to handle that case yourself.
    public func waitForSleeper() async throws {
        try await requireSleeper(within: Self.defaultWaitTimeout)
    }

    func requireSleeper(within timeout: Duration) async throws {
        guard await waitForSleeper(timeout: timeout) || Task.isCancelled else { throw WaitTimeout(timeout: timeout) }
    }

    /// Waits for a sleeper, then advances exactly to the earliest deadline. Returns how long that was.
    ///
    /// Throws ``WaitTimeout`` like ``waitForSleeper()``.
    @discardableResult
    public func advanceToNextSleeper() async throws -> Duration {
        try await waitForSleeper()
        let step = state.withLock { state -> Duration in
            guard let earliest = state.sleepers.map(\.deadline).min() else { return .zero }
            return max(.zero, state.current.duration(to: earliest))
        }
        advance(by: step)
        return step
    }

    /// Returns once a task is sleeping, or when the calling task is cancelled.
    private func untilSleeperRegisters() async {
        let id = state.withLock { state -> Int in
            state.nextID += 1
            return state.nextID
        }
        await withTaskCancellationHandler {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let isReady = state.withLock { state -> Bool in
                    if !state.sleepers.isEmpty || state.cancelledWaiters.remove(id) != nil { return true }
                    state.waiters.append(Waiter(id: id, continuation: continuation))
                    return false
                }
                if isReady { continuation.resume() }
            }
        } onCancel: {
            let waiter = state.withLock { state -> Waiter? in
                guard let index = state.waiters.firstIndex(where: { $0.id == id }) else {
                    state.cancelledWaiters.insert(id)
                    return nil
                }
                return state.waiters.remove(at: index)
            }
            waiter?.continuation.resume()
        }
    }
}
