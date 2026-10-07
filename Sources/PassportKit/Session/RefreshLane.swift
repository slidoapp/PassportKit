/// The FIFO lane for operations that send the refresh token (ADR 0005).
///
/// A turn is reserved synchronously, when the operation is accepted, so the order of turns is the order of
/// calls even though the operations start later on their own tasks. The operation reads the refresh token
/// when its turn starts, never when it was queued, so it sees what the previous turn persisted.
///
/// Turns are held by tasks the manager owns and never cancels, so a reserved turn is always used and left.
struct RefreshLane {
    private var isBusy = false
    private var queue: [Completion<Void>] = []

    /// Reserves the next turn. The returned ticket completes when the turn starts.
    mutating func reserve() -> Completion<Void> {
        let ticket = Completion<Void>()
        if isBusy {
            queue.append(ticket)
        } else {
            isBusy = true
            ticket.complete(.success(()))
        }
        return ticket
    }

    /// Ends the current turn and starts the next one.
    mutating func leave() {
        if queue.isEmpty {
            isBusy = false
        } else {
            queue.removeFirst().complete(.success(()))
        }
    }
}

extension Completion where Value == Void {
    /// Waits for a lane turn. The waiting task is never cancelled, so this cannot be cut short.
    func turn() async {
        _ = try? await wait()
    }
}
