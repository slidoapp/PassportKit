import Foundation

// Names that appear only on the wire (ADR 0008, "Constants"). Open protocol values are structs elsewhere
// (`GrantType`, `PassportError.Code`, ...); JSON that is decoded through `Codable` uses `CodingKeys`.

/// Request parameters of form bodies and the authorization URL query.
package enum OAuthParameter {
    package static let grantType = "grant_type"  // RFC 6749 §4.1.3
    package static let clientID = "client_id"  // RFC 6749 §2.3.1
    package static let clientSecret = "client_secret"  // RFC 6749 §2.3.1
    package static let clientAssertion = "client_assertion"  // RFC 7521 §4.2
    package static let assertion = "assertion"  // RFC 7521 §4.1
    package static let password = "password"  // RFC 6749 §4.3.2
    package static let redirectURI = "redirect_uri"  // RFC 6749 §4.1.1
    package static let scope = "scope"  // RFC 6749 §3.3
    package static let resource = "resource"  // RFC 8707 §2
    package static let audience = "audience"  // RFC 8693 §2.1
    package static let code = "code"  // RFC 6749 §4.1.3
    package static let codeVerifier = "code_verifier"  // RFC 7636 §4.5
    package static let codeChallenge = "code_challenge"  // RFC 7636 §4.3
    package static let codeChallengeMethod = "code_challenge_method"  // RFC 7636 §4.3
    package static let state = "state"  // RFC 6749 §4.1.1
    package static let responseType = "response_type"  // RFC 6749 §4.1.1
    package static let refreshToken = "refresh_token"  // RFC 6749 §6
    package static let subjectToken = "subject_token"  // RFC 8693 §2.1
    package static let subjectTokenType = "subject_token_type"  // RFC 8693 §2.1
    package static let actorToken = "actor_token"  // RFC 8693 §2.1
    package static let actorTokenType = "actor_token_type"  // RFC 8693 §2.1
    package static let requestedTokenType = "requested_token_type"  // RFC 8693 §2.1
    package static let deviceCode = "device_code"  // RFC 8628 §3.4
    package static let token = "token"  // RFC 7009 §2.1
    package static let tokenTypeHint = "token_type_hint"  // RFC 7009 §2.1
    package static let loginHint = "login_hint"  // OpenID Connect Core §3.1.2.1
    package static let prompt = "prompt"  // OpenID Connect Core §3.1.2.1
}

/// Parameters of the authorization response, which arrives as the redirect query (RFC 6749 §4.1.2).
package enum AuthorizationResponseField {
    package static let code = "code"
    package static let state = "state"
    package static let error = "error"  // RFC 6749 §4.1.2.1
    package static let errorDescription = "error_description"
    package static let errorURI = "error_uri"
    package static let issuer = "iss"  // RFC 9207 §2
}

/// Members of an error response (RFC 6749 §5.2) and the same-named `WWW-Authenticate` parameters (RFC 6750 §3).
enum ErrorResponseField {
    static let error = "error"
    static let errorDescription = "error_description"
    static let errorURI = "error_uri"
}

/// Members of a successful token response (RFC 6749 §5.1, RFC 8693 §2.2.1).
enum TokenResponseField {
    static let accessToken = "access_token"
    static let tokenType = "token_type"
    static let expiresIn = "expires_in"
    static let refreshToken = "refresh_token"
    static let idToken = "id_token"  // OpenID Connect Core §3.1.3.3
    static let scope = "scope"
    static let issuedTokenType = "issued_token_type"  // RFC 8693 §2.2.1
}

/// Members of a device authorization response (RFC 8628 §3.2).
enum DeviceAuthorizationResponseField {
    static let deviceCode = "device_code"
    static let userCode = "user_code"
    static let verificationURI = "verification_uri"
    static let verificationURL = "verification_url"  // interoperability alias that predates RFC 8628
    static let verificationURIComplete = "verification_uri_complete"
    static let expiresIn = "expires_in"
    static let interval = "interval"
}

/// `response_type` values (RFC 6749 §3.1.1).
enum ResponseType {
    static let code = "code"
}

/// `code_challenge_method` values (RFC 7636 §4.2).
enum CodeChallengeMethod {
    static let s256 = "S256"
}

/// `token_type` values that are not an access token type registry entry of their own (RFC 8693 §2.2.1).
enum TokenTypeValue {
    static let notApplicable = "N_A"
}

/// HTTP authentication schemes (RFC 9110 §11).
enum AuthenticationScheme {
    static let bearer = "Bearer"  // RFC 6750
    static let basic = "Basic"  // RFC 7617

    /// Scheme names are case-insensitive (RFC 9110 §11.1).
    static func isBearer(_ scheme: String) -> Bool { scheme.caseInsensitiveCompare(bearer) == .orderedSame }
}

/// Media types of requests and responses (RFC 9110 §8.3).
enum MediaType {
    static let json = "application/json"
    static let formURLEncoded = "application/x-www-form-urlencoded"
}
