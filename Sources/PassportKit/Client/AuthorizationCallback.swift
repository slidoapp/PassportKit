import Foundation

/// Pure checks on an authorization response delivered to the redirect URI (RFC 6749 §4.1.2).
enum AuthorizationCallback {
    /// The response parameters that must not repeat (RFC 6749 §3.1).
    private static let uniqueNames: Set<String> = ["code", "state", "error", "error_description", "error_uri", "iss"]

    /// Whether `callback` is the redirect URI: scheme and host case-insensitively, port (default ports
    /// implied), and path exactly. The query is not compared; it carries the response.
    static func matches(_ callback: URL, redirectURI: URL) -> Bool {
        guard let actual = URLComponents(url: callback, resolvingAgainstBaseURL: false),
            let expected = URLComponents(url: redirectURI, resolvingAgainstBaseURL: false)
        else { return false }
        return actual.scheme?.lowercased() == expected.scheme?.lowercased()
            && actual.host?.lowercased() == expected.host?.lowercased()
            && effectivePort(actual) == effectivePort(expected)
            && normalizedPath(actual) == normalizedPath(expected)
    }

    /// The response parameters from the query (the fragment is not used: the response mode is `query`).
    ///
    /// Returns `nil` for malformed percent-encoding or when a response parameter appears more than once.
    static func parameters(of callback: URL) -> [String: String]? {
        guard let query = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.percentEncodedQuery else {
            return [:]
        }
        guard let pairs = FormEncoding.decode(Data(query.utf8)) else { return nil }
        var values: [String: String] = [:]
        for (name, value) in pairs {
            if values[name] != nil, uniqueNames.contains(name) { return nil }
            values[name] = value
        }
        return values
    }

    /// Compares two strings without returning early at the first differing byte. The length is not secret.
    static func constantTimeEquals(_ left: String, _ right: String) -> Bool {
        let lhs = Array(left.utf8)
        let rhs = Array(right.utf8)
        guard lhs.count == rhs.count else { return false }
        var difference: UInt8 = 0
        for index in lhs.indices { difference |= lhs[index] ^ rhs[index] }
        return difference == 0
    }

    private static func effectivePort(_ components: URLComponents) -> Int? {
        if let port = components.port { return port }
        switch components.scheme?.lowercased() {
        case "https": return 443
        case "http": return 80
        default: return nil
        }
    }

    private static func normalizedPath(_ components: URLComponents) -> String {
        components.percentEncodedPath.isEmpty ? "/" : components.percentEncodedPath
    }
}
