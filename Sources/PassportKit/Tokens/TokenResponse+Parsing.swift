import Foundation

extension TokenResponse {
    /// The longest `expires_in` accepted, in seconds (about 100 years); larger values are clamped.
    private static let maximumLifetimeSeconds = 3_153_600_000.0

    /// Parses the body of a 2xx token endpoint response (specification §7).
    ///
    /// Tolerates `expires_in` as a number or numeric string (unparsable values mean `nil`; negative values
    /// mean zero), a `null` member (treated as absent), and any unknown member (kept in ``additionalFields``).
    /// A known member of an unexpected type stays in ``additionalFields`` unparsed.
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/invalidResponse`` when the body is
    /// not a JSON object or lacks a non-empty `access_token` or a `token_type` string (RFC 6749 §5.1).
    init(parsing data: Data) throws {
        guard case .object(var members)? = try? JSONDecoder().decode(JSONValue.self, from: data) else {
            throw PassportError(.invalidResponse, errorDescription: "The token response is not a JSON object.")
        }
        let knownMembers = [
            "access_token", "token_type", "expires_in", "refresh_token", "id_token", "scope", "issued_token_type",
        ]
        for key in knownMembers where members[key] == .null {
            members[key] = nil
        }

        func takeString(_ key: String) -> String? {
            guard case .string(let text)? = members[key] else { return nil }
            members[key] = nil
            return text
        }

        guard let accessToken = takeString("access_token"), !accessToken.isEmpty else {
            throw PassportError(.invalidResponse, errorDescription: "The token response has no access_token.")
        }
        guard let tokenType = takeString("token_type"), !tokenType.isEmpty else {
            throw PassportError(.invalidResponse, errorDescription: "The token response has no token_type.")
        }

        var expiresIn: Duration?
        switch members["expires_in"] {
        case .number(let seconds)?:
            expiresIn = Self.lifetime(seconds: seconds)
            members["expires_in"] = nil
        case .string(let text)?:
            expiresIn = Double(text.trimmingCharacters(in: .whitespaces)).flatMap(Self.lifetime(seconds:))
            members["expires_in"] = nil
        default:
            break
        }

        self.init(
            accessToken: Secret(accessToken),
            tokenType: tokenType,
            expiresIn: expiresIn,
            refreshToken: takeString("refresh_token").flatMap { $0.isEmpty ? nil : Secret($0) },
            idToken: takeString("id_token").flatMap { $0.isEmpty ? nil : Secret($0) },
            scope: takeString("scope").map { ScopeSet(parsing: $0) },
            issuedTokenType: takeString("issued_token_type").map { TokenTypeIdentifier(rawValue: $0) },
            additionalFields: members
        )
    }

    private static func lifetime(seconds: Double) -> Duration? {
        guard seconds.isFinite else { return nil }
        return .seconds(min(max(seconds, 0), maximumLifetimeSeconds))
    }
}
