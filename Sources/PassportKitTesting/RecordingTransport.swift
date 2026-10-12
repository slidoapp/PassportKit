import Foundation
import HTTPTypes
import PassportKit

/// A request seen by a fake transport, with its form body decoded.
///
/// Descriptions and reflection show the method, the URL without query, userinfo or fragment, the header names
/// and the body size. They never show the body or any header value. ``request`` is the request as sent: it is
/// your value, and `HTTPTypes.HTTPRequest` prints its URL with query and, under `dump`, its header fields.
public struct RecordedRequest: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    /// The request as sent.
    public let request: HTTPRequest
    /// The request body, if any.
    public let body: Data?

    /// Wraps `request` and its `body`.
    public init(_ request: HTTPRequest, body: Data? = nil) {
        self.request = request
        self.body = body
    }

    /// The HTTP method.
    public var method: HTTPRequest.Method { request.method }
    /// The URL, or `nil` for a request without an absolute one.
    public var url: URL? { request.url }
    /// The URL path without the query.
    public var path: String { url?.path ?? "" }
    /// The header fields.
    public var headerFields: HTTPFields { request.headerFields }

    /// The decoded form parameters in wire order; empty when there is no form body.
    public var form: [(name: String, value: String)] {
        body.flatMap { FormEncoding.decode($0) }?.map { (name: $0.0, value: $0.1) } ?? []
    }
    /// The form parameter names in wire order.
    public var formNames: [String] { form.map(\.name) }

    /// The first form value named `name`.
    public func value(_ name: String) -> String? { form.first { $0.name == name }?.value }
    /// Every form value named `name`, in order.
    public func values(_ name: String) -> [String] { form.filter { $0.name == name }.map(\.value) }

    /// A redacted one-line summary.
    public var description: String {
        let target = url?.redactedTarget ?? "<no url>"
        let bodySize = body.map { "\($0.count) bytes" } ?? "none"
        return "RecordedRequest(\(method.rawValue) \(target), headers: \(headerFields.names), body: \(bodySize))"
    }

    /// Same as ``description``.
    public var debugDescription: String { description }

    /// A mirror exposing the summary only.
    public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
}

/// A transport that plays back scripted steps in order and records every request.
///
/// Running out of steps fails the call with ``ScriptExhausted`` so a test that sends too much fails loudly.
public actor RecordingTransport: HTTPTransport {
    /// One scripted outcome.
    ///
    /// Descriptions and reflection show the status and the header names, never header values or the body.
    public enum Step: Sendable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
        /// Answer with a response and its body.
        case respond(HTTPResponse, body: Data = Data())
        /// Fail the call with a transport error.
        case fail(any Error)

        /// A summary without header values or body.
        public var description: String {
            switch self {
            case .respond(let response, let body):
                "Step.respond(status: \(response.status.code), headers: \(response.headerFields.names), body: \(body.count) bytes)"
            case .fail: "Step.fail"
            }
        }

        /// Same as ``description``.
        public var debugDescription: String { description }

        /// A mirror exposing the summary only.
        public var customMirror: Mirror { Mirror(self, children: ["summary": description], displayStyle: .struct) }
    }

    /// Thrown when a request arrives and no step is left.
    public struct ScriptExhausted: Error {}

    private var steps: [Step]
    /// Every request received, in order, including the ones that failed.
    public private(set) var requests: [RecordedRequest] = []

    /// Creates a transport with an initial script.
    public init(_ steps: [Step] = []) { self.steps = steps }

    /// Appends a step to the script.
    public func enqueue(_ step: Step) { steps.append(step) }

    public func send(_ request: HTTPRequest, body: Data?) async throws -> (HTTPResponse, Data) {
        requests.append(RecordedRequest(request, body: body))
        guard !steps.isEmpty else { throw ScriptExhausted() }
        switch steps.removeFirst() {
        case .respond(let response, let body): return (response, body)
        case .fail(let error): throw error
        }
    }
}

extension RecordingTransport.Step {
    /// A JSON response with `status` and a raw `body`.
    public static func json(_ status: Int = 200, _ body: String, headers: HTTPFields = [:]) -> Self {
        .respond(HTTPResponse(status: .init(code: status), headerFields: headers), body: Data(body.utf8))
    }

    /// A 200 token response; `extra` is raw JSON members appended after `expires_in` (start with a comma).
    public static func tokens(_ accessToken: String = "at", extra: String = "") -> Self {
        .json(200, #"{"access_token":"\#(accessToken)","token_type":"Bearer","expires_in":3600\#(extra)}"#)
    }

    /// An RFC 6749 §5.2 error response.
    public static func oauthError(_ code: String, status: Int = 400, headers: HTTPFields = [:]) -> Self {
        .json(status, #"{"error":"\#(code)"}"#, headers: headers)
    }
}
