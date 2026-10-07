/// What to do with a resource-server response (RFC 6750 §3.1), decided by
/// ``RequestAuthorizer/evaluate(statusCode:headers:token:attempt:)``.
///
/// Cases may be added in a minor release: the enumeration is not frozen, so a `switch` over it needs a `default`.
public enum RetryDecision: Sendable, Equatable {
    /// Hand the response to the caller.
    case deliver
    /// The token was rejected and has been invalidated: authorize the request again and resend it once.
    case retry
    /// The request cannot succeed with this session; throw the error.
    case fail(PassportError)
}
