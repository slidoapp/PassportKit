import Foundation

@testable import PassportKit

/// A request seen by ``RecordingTransport`` with its form body decoded.
struct RecordedRequest: Sendable {
    let request: HTTPRequest

    var form: [(String, String)] { request.body.flatMap { FormEncoding.decode($0) } ?? [] }
    var formNames: [String] { form.map(\.0) }

    func value(_ name: String) -> String? { form.first { $0.0 == name }?.1 }
    func values(_ name: String) -> [String] { form.filter { $0.0 == name }.map(\.1) }
}

/// Test-only transport that plays back scripted steps in order and records every request.
///
/// Running out of steps fails the call with a transport error so a test that sends too much fails loudly.
actor RecordingTransport: HTTPTransport {
    enum Step: Sendable {
        case respond(HTTPResponse)
        case fail(any Error)
    }

    struct ScriptExhausted: Error {}

    private var steps: [Step]
    private(set) var requests: [RecordedRequest] = []

    init(_ steps: [Step] = []) {
        self.steps = steps
    }

    func enqueue(_ step: Step) { steps.append(step) }

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        requests.append(RecordedRequest(request: request))
        guard !steps.isEmpty else { throw ScriptExhausted() }
        switch steps.removeFirst() {
        case .respond(let response): return response
        case .fail(let error): throw error
        }
    }
}

extension RecordingTransport.Step {
    static func json(_ status: Int = 200, _ body: String, headers: HTTPHeaders = [:]) -> Self {
        .respond(HTTPResponse(statusCode: status, headers: headers, body: Data(body.utf8)))
    }

    static func tokens(_ accessToken: String = "at", extra: String = "") -> Self {
        .json(200, #"{"access_token":"\#(accessToken)","token_type":"Bearer","expires_in":3600\#(extra)}"#)
    }

    static func oauthError(_ code: String, status: Int = 400, headers: HTTPHeaders = [:]) -> Self {
        .json(status, #"{"error":"\#(code)"}"#, headers: headers)
    }
}
