/// A recognisable value that must never appear in any description of a public type.
enum Canary {
    static let value = "CANARY-9f3a1c77e2d84b05"

    /// Every textual rendering of `subject` that a log line or debugger could produce.
    static func renderings(of subject: some Any) -> [String] {
        var dumped = ""
        dump(subject, to: &dumped)
        return [
            String(describing: subject),
            String(reflecting: subject),
            "\(subject)",
            dumped,
        ]
    }
}
