/// Measures elapsed time on an injected `any Clock<Duration>`.
///
/// `Clock.Instant` is an associated type, so it cannot be stored for an existential clock. The stopwatch
/// opens the existential once and keeps the starting instant inside a closure (ADR 0006).
struct Stopwatch: Sendable {
    private let reading: @Sendable () -> Duration

    /// Starts measuring now.
    init(clock: any Clock<Duration>) {
        func start<C: Clock<Duration>>(_ clock: C) -> @Sendable () -> Duration {
            let origin = clock.now
            return { origin.duration(to: clock.now) }
        }
        reading = start(clock)
    }

    /// The time since the stopwatch started.
    var elapsed: Duration { reading() }
}
