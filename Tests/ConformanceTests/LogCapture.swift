import Logging

/// One captured log line.
struct LogLine: Sendable {
    var level: Logger.Level
    var message: String
    var metadata: Logger.Metadata
}

/// Records every line of the loggers it hands out. Installed per test through the `logger:` parameters,
/// because `LoggingSystem.bootstrap` is global and can run once.
final class LogCapture: Sendable {
    private let storage = Locked<[LogLine]>([])

    var lines: [LogLine] { storage.read() }

    /// A logger at `.trace` that records into this capture.
    var logger: Logger {
        var logger = Logger(label: "test", factory: { _ in Handler(capture: self) })
        logger.logLevel = .trace
        return logger
    }

    /// Every message and metadata key and value, as text, for canary searches.
    var renderings: [String] {
        lines.flatMap { line in
            [line.message] + line.metadata.flatMap { [$0.key, String(describing: $0.value)] }
        }
    }

    func contains(_ message: String, level: Logger.Level? = nil) -> Bool {
        lines.contains { $0.message == message && (level == nil || $0.level == level) }
    }

    private struct Handler: LogHandler {
        let capture: LogCapture
        var metadata: Logger.Metadata = [:]
        var logLevel: Logger.Level = .trace

        subscript(metadataKey key: String) -> Logger.Metadata.Value? {
            get { metadata[key] }
            set { metadata[key] = newValue }
        }

        func log(event: LogEvent) {
            let merged = metadata.merging(event.metadata ?? [:]) { $1 }
            capture.storage.update {
                $0.append(LogLine(level: event.level, message: "\(event.message)", metadata: merged))
            }
        }
    }
}
