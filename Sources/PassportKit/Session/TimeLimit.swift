/// Runs `operation` and gives up on it after `limit` on `clock`.
///
/// Returns `nil` when the limit passed first; the operation is then cancelled. An error from the operation
/// is rethrown.
func withTimeLimit<Value: Sendable>(
    _ limit: Duration,
    clock: any Clock<Duration>,
    operation: @escaping @Sendable () async throws -> Value
) async throws -> Value? {
    try await withThrowingTaskGroup(of: Value?.self) { group in
        group.addTask { try await operation() }
        group.addTask {
            try await clock.sleep(for: limit)
            return nil
        }
        defer { group.cancelAll() }
        return try await group.next() ?? nil
    }
}
