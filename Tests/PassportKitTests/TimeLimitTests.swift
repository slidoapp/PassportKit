import Foundation
import PassportKitTesting
import Testing

@testable import PassportKit

@Suite("withTimeLimit", .timeLimit(.minutes(1)))
struct TimeLimitTests {
    final class DoneFlag: @unchecked Sendable {
        // @unchecked Sendable: the value is only touched under `lock`.
        private let lock = NSLock()
        private var value = false
        var isRaised: Bool { lock.withLock { value } }
        func raise() { lock.withLock { value = true } }
    }

    /// An operation that ignores cancellation until released, like a transport that cannot be interrupted.
    final class Stubborn: @unchecked Sendable {
        // @unchecked Sendable: the continuation is only touched under `lock`.
        private let lock = NSLock()
        private var continuation: CheckedContinuation<Void, Never>?
        private var isReleased = false

        func run() async {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let proceed = lock.withLock { () -> Bool in
                    if isReleased { return true }
                    self.continuation = continuation
                    return false
                }
                if proceed { continuation.resume() }
            }
        }

        func release() {
            let parked = lock.withLock { () -> CheckedContinuation<Void, Never>? in
                isReleased = true
                defer { continuation = nil }
                return continuation
            }
            parked?.resume()
        }
    }

    @Test("returns when the limit passes even if the operation ignores cancellation")
    func giveUpOnStubbornOperation() async throws {
        let clock = ManualClock()
        let stubborn = Stubborn()
        let isDone = DoneFlag()
        let limited = Task {
            defer { isDone.raise() }
            return try await withTimeLimit(.seconds(5), clock: clock) { await stubborn.run() }
        }
        await clock.advanceToNextSleeper()
        let deadline = ContinuousClock.now.advanced(by: .seconds(2))
        while !isDone.isRaised, ContinuousClock.now < deadline { await Task.yield() }
        #expect(isDone.isRaised, "the limit waited for an operation that ignores cancellation")
        stubborn.release()
        #expect(try await limited.value == nil)
    }

    @Test("returns the result, or rethrows the error, of an operation that finishes first")
    func finishesFirst() async throws {
        let clock = ManualClock()
        #expect(try await withTimeLimit(.seconds(5), clock: clock) { 42 } == 42)
        struct Failure: Error {}
        await #expect(throws: Failure.self) {
            try await withTimeLimit(.seconds(5), clock: clock) { throw Failure() } as Int?
        }
    }

    @Test("stops waiting when the caller is cancelled")
    func callerCancelled() async throws {
        let clock = ManualClock()
        let stubborn = Stubborn()
        let limited = Task { try await withTimeLimit(.seconds(5), clock: clock) { await stubborn.run() } }
        await clock.waitForSleeper()
        limited.cancel()
        await #expect(throws: CancellationError.self) { try await limited.value }
        stubborn.release()
    }
}
