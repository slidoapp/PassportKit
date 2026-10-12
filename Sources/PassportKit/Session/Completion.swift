import Foundation
import os

/// A one-shot result that any number of callers can await, and stop awaiting when they are cancelled.
///
/// This is how an in-flight operation is shared: the operation runs in a task the manager owns, and every
/// caller (including the one that started it) only waits here. Cancelling a waiter resumes that waiter with
/// `CancellationError` and does nothing to the operation.
final class Completion<Value: Sendable>: Sendable {
    private struct State {
        var outcome: Result<Value, any Error>?
        var waiters: [Int: CheckedContinuation<Value, any Error>] = [:]
        /// Waiters cancelled before they parked their continuation.
        var cancelled: Set<Int> = []
        var nextIdentifier = 0
    }

    // Continuations are resumed outside the lock.
    private let state = OSAllocatedUnfairLock(initialState: State())

    /// Stores the result and resumes every waiter. Only the first call has an effect.
    func complete(_ result: Result<Value, any Error>) {
        let parked = state.withLock { state -> [CheckedContinuation<Value, any Error>] in
            guard state.outcome == nil else { return [] }
            state.outcome = result
            defer { state.waiters = [:] }
            return Array(state.waiters.values)
        }
        for waiter in parked { waiter.resume(with: result) }
    }

    /// Returns the result, or throws `CancellationError` as soon as the calling task is cancelled.
    func wait() async throws -> Value {
        let identifier = state.withLock { state in
            state.nextIdentifier += 1
            return state.nextIdentifier
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Value, any Error>) in
                let immediate = state.withLock { state -> Result<Value, any Error>? in
                    if state.cancelled.remove(identifier) != nil { return .failure(CancellationError()) }
                    if let outcome = state.outcome { return outcome }
                    state.waiters[identifier] = continuation
                    return nil
                }
                if let immediate { continuation.resume(with: immediate) }
            }
        } onCancel: {
            let parked = state.withLock { state -> CheckedContinuation<Value, any Error>? in
                if let parked = state.waiters.removeValue(forKey: identifier) { return parked }
                if state.outcome == nil { state.cancelled.insert(identifier) }
                return nil
            }
            parked?.resume(throwing: CancellationError())
        }
    }
}
