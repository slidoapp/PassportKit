import Foundation

extension URL {
    /// The URL without query, userinfo or fragment, for descriptions: a query can carry credentials, such as the
    /// authorization code of a redirect.
    package var redactedTarget: String {
        guard var components = URLComponents(url: self, resolvingAgainstBaseURL: false) else { return "<url>" }
        components.query = nil
        components.fragment = nil
        components.user = nil
        components.password = nil
        return components.string ?? "<url>"
    }
}
