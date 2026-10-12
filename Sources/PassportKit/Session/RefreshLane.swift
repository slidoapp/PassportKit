import os

/// The FIFO lane for operations that send the refresh token (ADR 0005).
///
/// A turn is reserved synchronously, when the operation is accepted, so the order of turns is the order of
/// calls even though the operations start later on their own tasks. The operation reads the refresh token
/// when its turn starts, never when it was queued, so it sees what the previous turn persisted.
///
/// Turns are held by tasks the manager owns and never cancels, so a reserved turn is always used and left.
/// Each session has a lane of its own (ADR 0007): turns of an ended session finish on its old lane, so a
/// request of that session that never answers cannot hold up the next one.
final class RefreshLane: Sendable {
    /// A reserved place in a lane.
    struct Turn {
        fileprivate let lane: RefreshLane
        fileprivate let ticket: Completion<Void>

        /// Waits for the turn to start. The waiting task is never cancelled, so this cannot be cut short.
        func start() async {
            _ = try? await ticket.wait()
        }

        /// Ends the turn and starts the next one.
        func finish() { lane.leave() }
    }

    private struct State {
        var isBusy = false
        var queue: [Completion<Void>] = []
    }

    // Turns are reserved and finished on the owning `TokenManager` actor, so the lock is never contended; it
    // makes the lane `Sendable` so that a turn can be carried into the tasks that run on that actor.
    private let state = OSAllocatedUnfairLock(initialState: State())

    /// Reserves the next turn.
    func reserve() -> Turn {
        let ticket = Completion<Void>()
        let starts = state.withLock { state in
            if state.isBusy {
                state.queue.append(ticket)
                return false
            }
            state.isBusy = true
            return true
        }
        if starts { ticket.complete(.success(())) }
        return Turn(lane: self, ticket: ticket)
    }

    private func leave() {
        let next = state.withLock { state -> Completion<Void>? in
            if state.queue.isEmpty {
                state.isBusy = false
                return nil
            }
            return state.queue.removeFirst()
        }
        next?.complete(.success(()))
    }
}
