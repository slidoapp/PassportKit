import Foundation

/// The single error type thrown by PassportKit (ADR 0003).
///
/// ``code`` preserves the server's OAuth error code; ``recovery`` tells the caller what to do.
/// Cancellation is never wrapped: `CancellationError` propagates unchanged. Descriptions never
/// include the underlying error, response bodies or any credential.
public struct PassportError: LocalizedError, Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    /// The largest number of characters kept in ``detail``.
    static let maximumDescriptionLength = 200

    /// The error code: an OAuth error code (RFC 6749 §5.2) or a client-side code.
    public var code: Code
    /// What the caller should do next.
    public var recovery: Recovery
    /// The HTTP status of the response that produced the error, if any. Recorded, never used for classification.
    public var statusCode: Int?
    /// The server's `error_description` or the library's own explanation, with control characters removed,
    /// token-like runs redacted and truncated to 200 characters. For display only; never use it for logic.
    public internal(set) var detail: String?
    /// The server's `error_uri` (RFC 6749 §5.2), if any.
    public var errorURI: URL?
    /// The lower-level error, such as a `URLError`. Never printed by ``description``.
    public var underlying: (any Error & Sendable)?

    /// Creates an error with an explicit ``recovery``.
    public init(
        _ code: Code,
        recovery: Recovery,
        statusCode: Int? = nil,
        detail: String? = nil,
        errorURI: URL? = nil,
        underlying: (any Error & Sendable)? = nil
    ) {
        self.code = code
        self.recovery = recovery
        self.statusCode = statusCode
        self.detail = detail.map(Self.sanitize)
        self.errorURI = errorURI
        self.underlying = underlying
    }

    /// Creates an error whose ``recovery`` is the one the specification table gives `code` without request
    /// context (no `Retry-After`).
    public init(
        _ code: Code,
        statusCode: Int? = nil,
        detail: String? = nil,
        errorURI: URL? = nil,
        underlying: (any Error & Sendable)? = nil
    ) {
        self.init(
            code,
            recovery: Self.recovery(for: code, context: .other, statusCode: statusCode, retryAfter: nil),
            statusCode: statusCode,
            detail: detail,
            errorURI: errorURI,
            underlying: underlying
        )
    }

    /// Equal when ``code``, ``recovery`` and ``statusCode`` are equal.
    public static func == (lhs: PassportError, rhs: PassportError) -> Bool {
        lhs.code == rhs.code && lhs.recovery == rhs.recovery && lhs.statusCode == rhs.statusCode
    }

    /// A one-line summary with code, recovery, status and the sanitized description.
    public var description: String {
        var parts = ["code: \(code.rawValue)", "recovery: \(recovery)"]
        if let statusCode { parts.append("status: \(statusCode)") }
        if let detail { parts.append("description: \(detail)") }
        if let underlying { parts.append("underlying: \(type(of: underlying))") }
        return "PassportError(\(parts.joined(separator: ", ")))"
    }

    /// What `localizedDescription` returns: the redacted ``description``, so a generic `catch` that prints an error
    /// shows the code and the sanitized ``detail`` and never a credential.
    public var errorDescription: String? { description }

    /// Same as ``description``.
    public var debugDescription: String { description }

    /// A mirror exposing the summary only, so reflection cannot reach the underlying error.
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }

    /// Replaces control and line-separator characters, drops invisible format characters (bidirectional overrides,
    /// zero-width characters), redacts runs of 24 or more token-like characters (a token echoed by a
    /// server would look like one) and truncates to 200 characters.
    static func sanitize(_ text: String) -> String {
        var output = ""
        var run = ""
        func flushRun() {
            output += run.count >= 24 ? "<redacted>" : run
            run = ""
        }
        for scalar in text.unicodeScalars {
            if Self.isTokenCharacter(scalar) {
                run.unicodeScalars.append(scalar)
                continue
            }
            flushRun()
            switch scalar.properties.generalCategory {
            case .control, .lineSeparator, .paragraphSeparator: output += " "
            case .format: break  // bidirectional overrides and other invisible characters can disguise text
            default: output.unicodeScalars.append(scalar)
            }
        }
        flushRun()
        return String(output.prefix(maximumDescriptionLength))
    }

    private static func isTokenCharacter(_ scalar: Unicode.Scalar) -> Bool {
        switch scalar {
        case "A"..."Z", "a"..."z", "0"..."9", "-", ".", "_", "~", "+", "/", "=": true
        default: false
        }
    }
}
