import Foundation

/// What to ask for in an authorization code request (RFC 6749 §4.1.1).
///
/// PKCE (S256), `state` and the client identifier are added by
/// ``OAuthClient/beginAuthorization(_:)``.
public struct AuthorizationRequest: Sendable, Hashable {
    /// One value of the `prompt` parameter (OpenID Connect Core §3.1.2.1). An open set: servers define more.
    public struct Prompt: RawRepresentable, Sendable, Hashable {
        /// The `prompt` value as sent.
        public let rawValue: String

        /// Creates a prompt from its `prompt` value.
        public init(rawValue: String) {
            self.rawValue = rawValue
        }

        /// `none`: show no authentication or consent screen; fail if one would be needed. Named for what it asks,
        /// so it never reads as "no value".
        public static let noInteraction = Prompt(rawValue: "none")
        /// `login`: ask the user to authenticate again.
        public static let login = Prompt(rawValue: "login")
        /// `consent`: ask the user for consent again.
        public static let consent = Prompt(rawValue: "consent")
        /// `select_account`: let the user choose an account.
        public static let selectAccount = Prompt(rawValue: "select_account")
    }

    /// Where the authorization server sends the user back (`redirect_uri`, RFC 6749 §3.1.2).
    ///
    /// Must be absolute, without fragment, and use `https`, a private-use scheme, or `http` on a loopback host
    /// (RFC 8252 §7). For a loopback redirect put the actual port in the URI: the callback is compared with it.
    public var redirectURI: URL
    /// The requested scope (RFC 6749 §3.3); omitted when `nil` or empty.
    public var scope: ScopeSet?
    /// Resource indicators, sent as repeated `resource` parameters (RFC 8707 §2).
    public var resources: [URL]
    /// `login_hint`, a hint for the authentication step (OpenID Connect Core §3.1.2.1).
    public var loginHint: String?
    /// `prompt` values (OpenID Connect Core §3.1.2.1), sent as one space-delimited parameter in the given order;
    /// omitted when empty. ``Prompt/noInteraction`` must not be combined with other values.
    public var prompt: [Prompt]
    /// Extension parameters appended after the standard ones; a colliding name is an `invalidConfiguration` error.
    public var additionalParameters: AdditionalParameters
    /// How long the user has to complete the request, measured on the client's injected clock; 10 minutes by
    /// default. Must be positive.
    public var lifetime: Duration

    /// Creates a request.
    public init(
        redirectURI: URL,
        scope: ScopeSet? = nil,
        resources: [URL] = [],
        loginHint: String? = nil,
        prompt: [Prompt] = [],
        additionalParameters: AdditionalParameters = [:],
        lifetime: Duration = .seconds(600)
    ) {
        self.redirectURI = redirectURI
        self.scope = scope
        self.resources = resources
        self.loginHint = loginHint
        self.prompt = prompt
        self.additionalParameters = additionalParameters
        self.lifetime = lifetime
    }
}

/// Presents an authorization URL to the user and returns the redirect, for example in a system browser sheet
/// (RFC 8252 §4). The library never opens a browser itself.
public protocol AuthorizationUserAgent: Sendable {
    /// Presents `url` and returns the callback URL that matched `redirectURI`.
    ///
    /// Throw ``PassportError`` with code ``PassportError/Code-swift.struct/userCancelled`` when the user
    /// dismisses the agent, and honour task cancellation.
    func present(_ url: URL, redirectURI: URL) async throws -> URL
}
