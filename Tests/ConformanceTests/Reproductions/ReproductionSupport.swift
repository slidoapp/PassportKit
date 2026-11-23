import Logging

extension LogLine {
    /// The value of the metadata `key` as text, or `nil` when the line has no such key.
    func value(_ key: String) -> String? { metadata[key].map { "\($0)" } }
}

extension LogCapture {
    /// The lines logged after the first `count` lines.
    func lines(after count: Int) -> [LogLine] { Array(lines.dropFirst(count)) }
}
