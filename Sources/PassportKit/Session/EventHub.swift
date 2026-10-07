import Foundation

/// Fans session events out to any number of `AsyncStream` subscribers.
///
/// Subscribing must work from nonisolated code (`TokenManager.events`), so the hub is a lock-guarded class
/// rather than part of the actor's state.
final class EventHub: @unchecked Sendable {
    // @unchecked Sendable: `continuations` and `isFinished` are only touched under `lock`; events are yielded
    // outside it.
    private let lock = NSLock()
    private var continuations: [Int: AsyncStream<SessionEvent>.Continuation] = [:]
    private var nextIdentifier = 0
    private var isFinished = false

    /// A new stream that receives every event emitted from now on. It ends when the hub finishes.
    func subscribe() -> AsyncStream<SessionEvent> {
        AsyncStream { continuation in
            let identifier = lock.withLock { () -> Int? in
                guard !isFinished else { return nil }
                nextIdentifier += 1
                continuations[nextIdentifier] = continuation
                return nextIdentifier
            }
            guard let identifier else { return continuation.finish() }
            continuation.onTermination = { [weak self] _ in
                self?.lock.withLock { _ = self?.continuations.removeValue(forKey: identifier) }
            }
        }
    }

    func emit(_ event: SessionEvent) {
        let subscribers = lock.withLock { Array(continuations.values) }
        for subscriber in subscribers { subscriber.yield(event) }
    }

    /// Ends every stream. Later subscriptions end immediately.
    func finish() {
        let subscribers = lock.withLock { () -> [AsyncStream<SessionEvent>.Continuation] in
            isFinished = true
            defer { continuations = [:] }
            return Array(continuations.values)
        }
        for subscriber in subscribers { subscriber.finish() }
    }
}
