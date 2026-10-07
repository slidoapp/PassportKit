import Foundation
import PassportKit

/// A request seen by a fake transport, with its form body decoded.
public struct RecordedRequest: Sendable {
    /// The request as sent.
    public let request: HTTPRequest

    /// Wraps `request`.
    public init(_ request: HTTPRequest) { self.request = request }

    /// The HTTP method.
    public var method: HTTPMethod { request.method }
    /// The URL.
    public var url: URL { request.url }
    /// The URL path.
    public var path: String { request.url.path }
    /// The headers.
    public var headers: HTTPHeaders { request.headers }

    /// The decoded form parameters in wire order; empty when there is no form body.
    public var form: [(name: String, value: String)] {
        request.body.flatMap { FormEncoding.decode($0) }?.map { (name: $0.0, value: $0.1) } ?? []
    }
    /// The form parameter names in wire order.
    public var formNames: [String] { form.map(\.name) }

    /// The first form value named `name`.
    public func value(_ name: String) -> String? { form.first { $0.name == name }?.value }
    /// Every form value named `name`, in order.
    public func values(_ name: String) -> [String] { form.filter { $0.name == name }.map(\.value) }
}

/// A transport that plays back scripted steps in order and records every request.
///
/// Running out of steps fails the call with ``ScriptExhausted`` so a test that sends too much fails loudly.
public actor RecordingTransport: HTTPTransport {
    /// One scripted outcome.
    public enum Step: Sendable {
        /// Answer with a response.
        case respond(HTTPResponse)
        /// Fail the call with a transport error.
        case fail(any Error)
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

    public func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        requests.append(RecordedRequest(request))
        guard !steps.isEmpty else { throw ScriptExhausted() }
        switch steps.removeFirst() {
        case .respond(let response): return response
        case .fail(let error): throw error
        }
    }
}

extension RecordingTransport.Step {
    /// A JSON response with `status` and a raw `body`.
    public static func json(_ status: Int = 200, _ body: String, headers: HTTPHeaders = [:]) -> Self {
        .respond(HTTPResponse(statusCode: status, headers: headers, body: Data(body.utf8)))
    }

    /// A 200 token response; `extra` is raw JSON members appended after `expires_in` (start with a comma).
    public static func tokens(_ accessToken: String = "at", extra: String = "") -> Self {
        .json(200, #"{"access_token":"\#(accessToken)","token_type":"Bearer","expires_in":3600\#(extra)}"#)
    }

    /// An RFC 6749 §5.2 error response.
    public static func oauthError(_ code: String, status: Int = 400, headers: HTTPHeaders = [:]) -> Self {
        .json(status, #"{"error":"\#(code)"}"#, headers: headers)
    }
}
