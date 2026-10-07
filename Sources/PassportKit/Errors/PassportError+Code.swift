extension PassportError {
    /// An open set of error codes: server codes are preserved verbatim.
    ///
    /// Client-side codes use a `client.` raw value prefix to keep them apart from OAuth codes.
    public struct Code: RawRepresentable, Sendable, Hashable {
        /// The code string as sent by the server, or the prefixed client-side string.
        public let rawValue: String

        /// Creates a code from its string.
        public init(rawValue: String) {
            self.rawValue = rawValue
        }

        /// The longest error code accepted from a server or a redirect.
        static let maximumServerLength = 64

        /// Accepts a code received from the network only when it is a well-formed `error` value of
        /// RFC 6749 §5.2 (`%x20-21 / %x23-5B / %x5D-7E`) of at most 64 characters, so hostile text never
        /// becomes a code that callers log or switch on. Returns `nil` otherwise.
        static func fromServer(_ text: String) -> Code? {
            let scalars = text.unicodeScalars
            guard !scalars.isEmpty, scalars.count <= maximumServerLength,
                scalars.allSatisfy({ ($0.value >= 0x20 && $0.value <= 0x7E) && $0 != "\"" && $0 != "\\" })
            else { return nil }
            return Code(rawValue: text)
        }

        /// `invalid_request` (RFC 6749 §5.2).
        public static let invalidRequest = Code(rawValue: "invalid_request")
        /// `invalid_client` (RFC 6749 §5.2).
        public static let invalidClient = Code(rawValue: "invalid_client")
        /// `invalid_grant` (RFC 6749 §5.2).
        public static let invalidGrant = Code(rawValue: "invalid_grant")
        /// `unauthorized_client` (RFC 6749 §5.2).
        public static let unauthorizedClient = Code(rawValue: "unauthorized_client")
        /// `unsupported_grant_type` (RFC 6749 §5.2).
        public static let unsupportedGrantType = Code(rawValue: "unsupported_grant_type")
        /// `invalid_scope` (RFC 6749 §5.2).
        public static let invalidScope = Code(rawValue: "invalid_scope")
        /// `invalid_target` (RFC 8707 §2).
        public static let invalidTarget = Code(rawValue: "invalid_target")
        /// `access_denied` (RFC 6749 §4.1.2.1, RFC 8628 §3.5).
        public static let accessDenied = Code(rawValue: "access_denied")
        /// `expired_token` (RFC 8628 §3.5).
        public static let expiredToken = Code(rawValue: "expired_token")
        /// `authorization_pending` (RFC 8628 §3.5).
        public static let authorizationPending = Code(rawValue: "authorization_pending")
        /// `slow_down` (RFC 8628 §3.5).
        public static let slowDown = Code(rawValue: "slow_down")
        /// `temporarily_unavailable` (RFC 6749 §4.1.2.1).
        public static let temporarilyUnavailable = Code(rawValue: "temporarily_unavailable")
        /// `server_error` (RFC 6749 §4.1.2.1).
        public static let serverError = Code(rawValue: "server_error")
        /// `invalid_token` (RFC 6750 §3.1).
        public static let invalidToken = Code(rawValue: "invalid_token")
        /// `insufficient_scope` (RFC 6750 §3.1).
        public static let insufficientScope = Code(rawValue: "insufficient_scope")

        /// The server response could not be understood, or exceeded a limit.
        public static let invalidResponse = Code(rawValue: "client.invalid_response")
        /// The client configuration or a request parameter is invalid.
        public static let invalidConfiguration = Code(rawValue: "client.invalid_configuration")
        /// The authorization response `state` did not match (RFC 6749 §10.12).
        public static let stateMismatch = Code(rawValue: "client.state_mismatch")
        /// The authorization response `iss` did not match the issuer (RFC 9207 §2.4).
        public static let issuerMismatch = Code(rawValue: "client.issuer_mismatch")
        /// The request did not complete: no connection, TLS failure, timeout.
        public static let transportFailure = Code(rawValue: "client.transport_failure")
        /// Credential storage failed.
        public static let storageFailure = Code(rawValue: "client.storage_failure")
        /// A token was issued but the app's acceptance policy rejected it.
        public static let tokenRejected = Code(rawValue: "client.token_rejected")
        /// There is no signed-in session.
        public static let notAuthenticated = Code(rawValue: "client.not_authenticated")
        /// The user dismissed the authorization user agent.
        public static let userCancelled = Code(rawValue: "client.user_cancelled")
        /// An operation exceeded its deadline.
        public static let timedOut = Code(rawValue: "client.timed_out")
        /// A resource server answered 401 and a retry with a fresh token did not help.
        public static let unauthorized = Code(rawValue: "client.unauthorized")
    }
}
