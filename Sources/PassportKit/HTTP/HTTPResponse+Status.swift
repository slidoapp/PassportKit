import HTTPTypes

extension HTTPResponse.Status {
    /// Whether the status reports a condition that may clear on its own: 429 Too Many Requests (RFC 6585 §4) or
    /// any 5xx server error (RFC 9110 §15.6).
    var isTransient: Bool { self == .tooManyRequests || kind == .serverError }

    /// Whether `code` is a transient status (``isTransient``). A number outside 0...999 is not a status code
    /// (RFC 9110 §15) and is not transient; `HTTPResponse.Status(code:)` would trap on it.
    static func isTransient(code: Int) -> Bool {
        (0...999).contains(code) && Self(code: code).isTransient
    }
}
