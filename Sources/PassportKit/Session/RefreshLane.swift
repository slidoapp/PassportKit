/// The FIFO lane for operations that send the refresh token (ADR 0005).
///
/// A turn is reserved synchronously, when the operation is accepted, so the order of turns is the order of
/// calls even though the operations start later on their own tasks. The operation reads the refresh token
/// when its turn starts, never when it was queued, so it sees what the previous turn persisted.
///
/// Turns are held by tasks the manager owns and never cancels, so a reserved turn is always used and left.
/// Each session has a lane of its own (ADR 0007): turns of an ended session finish on its old lane, so a
/// request of that session that never answers cannot hold up the next one.
final class RefreshLane: @unchecked Sendable {
    // @unchecked Sendable: the queue is only touched by code running on the owning `TokenManager` actor, where
    // turns are reserved and finished; a turn is merely carried into the tasks that run on that actor.

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

    private var isBusy = false
    private var queue: [Completion<Void>] = []

    /// Reserves the next turn.
    func reserve() -> Turn {
        let ticket = Completion<Void>()
        if isBusy {
            queue.append(ticket)
        } else {
            isBusy = true
            ticket.complete(.success(()))
        }
        return Turn(lane: self, ticket: ticket)
    }

    private func leave() {
        if queue.isEmpty {
            isBusy = false
        } else {
            queue.removeFirst().complete(.success(()))
        }
    }
}
