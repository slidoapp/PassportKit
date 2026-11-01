import HTTPTypes

extension HTTPResponse.Status {
    /// Whether the status reports a condition that may clear on its own: 429 Too Many Requests (RFC 6585 §4) or
    /// any 5xx server error (RFC 9110 §15.6).
    var isTransient: Bool { self == .tooManyRequests || kind == .serverError }
}
