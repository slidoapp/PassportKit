import Foundation
import PassportKit
import Testing

/// A credential store whose calls suspend until the test lets them continue, so a test can decide in which
/// order slow store operations take effect.
///
/// A held call has not touched the wrapped store yet: it takes effect when released. Calls that arrive while an
/// operation is not held run at once.
actor GatedStore: CredentialStore {
    enum Operation: Hashable { case save, delete }

    private let base = InMemoryCredentialStore()
    let log: OrderLog
    private var held: Set<Operation> = []
    private var suspended: [Operation: [CheckedContinuation<Void, Never>]] = [:]
    private var failingDeletes = 0

    /// Records "save" and "delete" in `log` when they take effect.
    init(log: OrderLog = OrderLog()) { self.log = log }

    /// Holds every later call of `operation` until ``release(_:)``.
    func hold(_ operation: Operation) { held.insert(operation) }

    /// Lets the held calls of `operation` continue, and stops holding it.
    func release(_ operation: Operation) {
        held.remove(operation)
        for continuation in suspended.removeValue(forKey: operation) ?? [] { continuation.resume() }
    }

    /// How many calls of `operation` are waiting to be released.
    func suspendedCount(_ operation: Operation) -> Int { suspended[operation]?.count ?? 0 }

    /// Makes the next `count` deletes throw.
    func failNextDeletes(_ count: Int = 1) { failingDeletes = count }

    func load(_ account: CredentialAccount) async throws -> Credential? { await base.load(account) }

    func save(_ credential: Credential, for account: CredentialAccount) async throws {
        await waitIfHeld(.save)
        try await base.save(credential, for: account)
        log.append("save")
    }

    func delete(_ account: CredentialAccount) async throws {
        await waitIfHeld(.delete)
        log.append("delete")
        if failingDeletes > 0 {
            failingDeletes -= 1
            throw PassportError(.storageFailure, errorDescription: "Deleting the credential failed.")
        }
        await base.delete(account)
    }

    private func waitIfHeld(_ operation: Operation) async {
        guard held.contains(operation) else { return }
        await withCheckedContinuation { suspended[operation, default: []].append($0) }
    }
}

/// Polls `condition` until it holds. Gives up after `timeout` of real time, so a broken implementation fails the
/// test instead of hanging it. Yields between polls; never sleeps.
func waitUntil(timeout: Duration = .seconds(5), _ condition: () async -> Bool) async -> Bool {
    let deadline = ContinuousClock.now.advanced(by: timeout)
    while ContinuousClock.now < deadline {
        if await condition() { return true }
        await Task.yield()
    }
    return await condition()
}

/// Whether `task` finishes (with a value or an error) within `timeout` of real time. Unlike awaiting the task, a
/// task that never finishes makes this return `false` instead of hanging the test.
func finishes<Value: Sendable, Failure: Error>(
    _ task: Task<Value, Failure>, within timeout: Duration = .seconds(2)
) async -> Bool {
    let flag = Flag()
    Task {
        _ = await task.result
        flag.raise()
    }
    return await waitUntil(timeout: timeout) { flag.isRaised }
}

final class Flag: @unchecked Sendable {
    // @unchecked Sendable: the value is only touched under `lock`.
    private let lock = NSLock()
    private var value = false
    var isRaised: Bool { lock.withLock { value } }
    func raise() { lock.withLock { value = true } }
}

/// Lets a test record the order of things that happen on different tasks and actors.
final class OrderLog: @unchecked Sendable {
    // @unchecked Sendable: the entries are only touched under `lock`.
    private let lock = NSLock()
    private var recorded: [String] = []
    var entries: [String] { lock.withLock { recorded } }
    func append(_ entry: String) { lock.withLock { recorded.append(entry) } }
}
