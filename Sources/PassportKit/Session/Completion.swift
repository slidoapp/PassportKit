import Foundation

/// A one-shot result that any number of callers can await, and stop awaiting when they are cancelled.
///
/// This is how an in-flight operation is shared: the operation runs in a task the manager owns, and every
/// caller (including the one that started it) only waits here. Cancelling a waiter resumes that waiter with
/// `CancellationError` and does nothing to the operation.
final class Completion<Value: Sendable>: @unchecked Sendable {
    // @unchecked Sendable: all mutable state is guarded by `lock`; continuations are resumed outside it.
    private let lock = NSLock()
    private var outcome: Result<Value, any Error>?
    private var waiters: [Int: CheckedContinuation<Value, any Error>] = [:]
    /// Waiters cancelled before they parked their continuation.
    private var cancelled: Set<Int> = []
    private var nextIdentifier = 0

    /// Stores the result and resumes every waiter. Only the first call has an effect.
    func complete(_ result: Result<Value, any Error>) {
        let parked = lock.withLock { () -> [CheckedContinuation<Value, any Error>] in
            guard outcome == nil else { return [] }
            outcome = result
            defer { waiters = [:] }
            return Array(waiters.values)
        }
        for waiter in parked { waiter.resume(with: result) }
    }

    /// Returns the result, or throws `CancellationError` as soon as the calling task is cancelled.
    func wait() async throws -> Value {
        let identifier = lock.withLock {
            nextIdentifier += 1
            return nextIdentifier
        }
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Value, any Error>) in
                let immediate = lock.withLock { () -> Result<Value, any Error>? in
                    if cancelled.remove(identifier) != nil { return .failure(CancellationError()) }
                    if let outcome { return outcome }
                    waiters[identifier] = continuation
                    return nil
                }
                if let immediate { continuation.resume(with: immediate) }
            }
        } onCancel: {
            let parked = lock.withLock { () -> CheckedContinuation<Value, any Error>? in
                if let parked = waiters.removeValue(forKey: identifier) { return parked }
                if outcome == nil { cancelled.insert(identifier) }
                return nil
            }
            parked?.resume(throwing: CancellationError())
        }
    }
}
