import Foundation

/// An HTTP response returned by an ``HTTPTransport``. Any status code is a normal response.
///
/// Descriptions and reflection show the status, header names and body size, never the body.
public struct HTTPResponse: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The HTTP status code.
    public var statusCode: Int
    /// The response headers.
    public var headers: HTTPHeaders
    /// The response body.
    public var body: Data

    /// Creates a response.
    public init(statusCode: Int, headers: HTTPHeaders = [:], body: Data = Data()) {
        self.statusCode = statusCode
        self.headers = headers
        self.body = body
    }

    /// A redacted one-line summary.
    public var description: String {
        "HTTPResponse(status: \(statusCode), headers: \(headers.names), body: \(body.count) bytes)"
    }

    /// A redacted one-line summary.
    public var debugDescription: String { description }

    /// A mirror exposing the redacted summary only.
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}
