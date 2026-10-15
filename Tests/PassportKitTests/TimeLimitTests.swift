import Foundation
import PassportKitTesting
import Testing
import os

@testable import PassportKit

@Suite("withTimeLimit", .timeLimit(.minutes(1)))
struct TimeLimitTests {
    final class DoneFlag: Sendable {
        private let value = OSAllocatedUnfairLock(initialState: false)
        var isRaised: Bool { value.withLock { $0 } }
        func raise() { value.withLock { $0 = true } }
    }

    /// An operation that ignores cancellation until released, like a transport that cannot be interrupted.
    final class Stubborn: Sendable {
        private struct State {
            var continuation: CheckedContinuation<Void, Never>?
            var isReleased = false
        }

        private let state = OSAllocatedUnfairLock(initialState: State())

        func run() async {
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                let proceed = state.withLock { state -> Bool in
                    if state.isReleased { return true }
                    state.continuation = continuation
                    return false
                }
                if proceed { continuation.resume() }
            }
        }

        func release() {
            let parked = state.withLock { state -> CheckedContinuation<Void, Never>? in
                state.isReleased = true
                defer { state.continuation = nil }
                return state.continuation
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
        try await clock.advanceToNextSleeper()
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
        try await clock.waitForSleeper()
        limited.cancel()
        await #expect(throws: CancellationError.self) { try await limited.value }
        stubborn.release()
    }
}
