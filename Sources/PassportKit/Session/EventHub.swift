import Foundation
import os

/// Fans session events out to any number of `AsyncStream` subscribers.
///
/// Each subscriber buffers at most ``bufferSize`` events it has not read yet; beyond that the oldest are dropped,
/// so a subscriber that stops reading cannot make the manager hold events for ever.
///
/// Subscribing must work from nonisolated code (`TokenManager.events`), so the hub is a lock-guarded class
/// rather than part of the actor's state.
final class EventHub: Sendable {
    static let bufferSize = 64

    private struct State {
        var continuations: [Int: AsyncStream<SessionEvent>.Continuation] = [:]
        var nextIdentifier = 0
        var isFinished = false
    }

    // Events are yielded outside the lock.
    private let state = OSAllocatedUnfairLock(initialState: State())

    /// A new stream that receives every event emitted from now on. It ends when the hub finishes.
    func subscribe() -> AsyncStream<SessionEvent> {
        AsyncStream(bufferingPolicy: .bufferingNewest(Self.bufferSize)) { continuation in
            let identifier = state.withLock { state -> Int? in
                guard !state.isFinished else { return nil }
                state.nextIdentifier += 1
                state.continuations[state.nextIdentifier] = continuation
                return state.nextIdentifier
            }
            guard let identifier else { return continuation.finish() }
            continuation.onTermination = { [weak self] _ in
                self?.state.withLock { _ = $0.continuations.removeValue(forKey: identifier) }
            }
        }
    }

    func emit(_ event: SessionEvent) {
        let subscribers = state.withLock { Array($0.continuations.values) }
        for subscriber in subscribers { subscriber.yield(event) }
    }

    /// Ends every stream. Later subscriptions end immediately.
    func finish() {
        let subscribers = state.withLock { state -> [AsyncStream<SessionEvent>.Continuation] in
            state.isFinished = true
            defer { state.continuations = [:] }
            return Array(state.continuations.values)
        }
        for subscriber in subscribers { subscriber.finish() }
    }
}
