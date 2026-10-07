import Foundation

/// An HTTP request handed to an ``HTTPTransport``.
///
/// Descriptions and reflection show the method, the URL without query, userinfo or fragment,
/// the header names and the body size. They never show the body or any header value.
public struct HTTPRequest: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The request method.
    public var method: HTTPMethod
    /// The target URL.
    public var url: URL
    /// The request headers.
    public var headers: HTTPHeaders
    /// The request body, if any.
    public var body: Data?

    /// Creates a request.
    public init(method: HTTPMethod, url: URL, headers: HTTPHeaders = [:], body: Data? = nil) {
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body
    }

    /// A redacted one-line summary.
    public var description: String {
        let target = Self.redactedTarget(of: url)
        let bodySize = body.map { "\($0.count) bytes" } ?? "none"
        return "HTTPRequest(\(method.rawValue) \(target), headers: \(headers.names), body: \(bodySize))"
    }

    /// A redacted one-line summary.
    public var debugDescription: String { description }

    /// A mirror exposing the redacted summary only.
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }

    static func redactedTarget(of url: URL) -> String {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else { return "<url>" }
        components.query = nil
        components.fragment = nil
        components.user = nil
        components.password = nil
        return components.string ?? "<url>"
    }
}
