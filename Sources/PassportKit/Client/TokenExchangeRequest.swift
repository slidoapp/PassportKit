import Foundation

/// A token exchange request (RFC 8693 §2.1).
public struct TokenExchangeRequest: Sendable {
    /// The token to exchange: `subject_token`.
    public var subjectToken: Secret
    /// The type of ``subjectToken``: `subject_token_type`.
    public var subjectTokenType: TokenTypeIdentifier
    /// A token representing the acting party: `actor_token`. Requires ``actorTokenType``.
    public var actorToken: Secret?
    /// The type of ``actorToken``: `actor_token_type`.
    public var actorTokenType: TokenTypeIdentifier?
    /// The type of token wanted: `requested_token_type`.
    public var requestedTokenType: TokenTypeIdentifier?
    /// Logical names of the target services, sent as repeated `audience` parameters (RFC 8693 §2.1).
    public var audiences: [String]
    /// Resource indicators, sent as repeated `resource` parameters (RFC 8707 §2).
    public var resources: [URL]
    /// The scope wanted.
    public var scope: ScopeSet?
    /// Extra parameters appended after the standard ones.
    public var additionalParameters: AdditionalParameters

    /// Creates a request.
    public init(
        subjectToken: Secret,
        subjectTokenType: TokenTypeIdentifier,
        actorToken: Secret? = nil,
        actorTokenType: TokenTypeIdentifier? = nil,
        requestedTokenType: TokenTypeIdentifier? = nil,
        audiences: [String] = [],
        resources: [URL] = [],
        scope: ScopeSet? = nil,
        additionalParameters: AdditionalParameters = [:]
    ) {
        self.subjectToken = subjectToken
        self.subjectTokenType = subjectTokenType
        self.actorToken = actorToken
        self.actorTokenType = actorTokenType
        self.requestedTokenType = requestedTokenType
        self.audiences = audiences
        self.resources = resources
        self.scope = scope
        self.additionalParameters = additionalParameters
    }
}
