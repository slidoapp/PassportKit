/// Runs `operation` and gives up on it after `limit` on `clock`.
///
/// Returns `nil` when the limit passed first; the operation is then cancelled. An error from the operation
/// is rethrown. Throws `CancellationError` when the calling task is cancelled.
///
/// The operation runs in a task of its own and this function waits only for whichever finishes first, the
/// operation or the limit. A structured task group would not do: it cannot return before its children finish,
/// and an operation that ignores cancellation (a transport that cannot be interrupted) would hold the caller
/// past the limit. Such an operation keeps running in the background until it ends.
func withTimeLimit<Value: Sendable>(
    _ limit: Duration,
    clock: any Clock<Duration>,
    operation: @escaping @Sendable () async throws -> Value
) async throws -> Value? {
    let outcome = Completion<Value?>()
    let work = Task {
        do {
            outcome.complete(.success(try await operation()))
        } catch {
            outcome.complete(.failure(error))
        }
    }
    let timer = Task {
        if (try? await clock.sleep(for: limit)) != nil { outcome.complete(.success(nil)) }
    }
    defer {
        work.cancel()
        timer.cancel()
    }
    return try await outcome.wait()
}
