import Foundation

extension Duration {
    /// The duration in seconds, for `Date` and `URLSessionConfiguration` arithmetic.
    package var timeInterval: TimeInterval { self / .seconds(1) }

    /// The duration in whole milliseconds, truncated toward zero, for log metadata.
    package var wholeMilliseconds: Int { Int(self / .milliseconds(1)) }
}
