extension PassportError {
    /// What the caller should do after a failure.
    public enum Recovery: Sendable, Hashable {
        /// The root grant is gone; the user must sign in again.
        case reauthenticate
        /// This resource or audience is not accessible; the session is intact.
        case resourceDenied
        /// Transient failure; retry, no sooner than `after` when given (`Retry-After`, RFC 9110 §10.2.3).
        case retryLater(after: Duration?)
        /// The client configuration or request is wrong; retrying cannot help.
        case fixConfiguration
        /// Nothing to recover from, for example the user declined.
        case none
    }
}
