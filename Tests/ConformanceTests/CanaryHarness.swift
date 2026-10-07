import Foundation
import PassportKit
import PassportKitTesting

/// A lock-protected value shared between the test and the transports and observers it hands out.
final class Locked<Value: Sendable>: @unchecked Sendable {
    // @unchecked Sendable: `value` is only read or written under `lock`.
    private let lock = NSLock()
    private var value: Value

    init(_ value: Value) { self.value = value }

    func read() -> Value { lock.withLock { value } }
    func update(_ change: (inout Value) -> Void) { lock.withLock { change(&value) } }
}

/// Every text rendering of every value a scenario produced. A canary in any of them is a leak.
final class RenderingLog: Sendable {
    private let renderings = Locked<[String]>([])

    var all: [String] { renderings.read() }

    /// Records `String(describing:)`, `String(reflecting:)` and `dump` of `value`.
    func look(_ value: Any) {
        var dumped = ""
        dump(value, to: &dumped)
        renderings.update { $0 += [String(describing: value), String(reflecting: value), dumped] }
    }

    /// Records an error the way an application would log it.
    func look(error: any Error) {
        look(error)
        renderings.update { $0.append(error.localizedDescription) }
        if let error = error as? PassportError {
            look(error.code)
            look(error.recovery)
            renderings.update { $0 += [error.errorDescription ?? "", error.errorURI?.absoluteString ?? ""] }
        }
    }

    /// Runs `operation`, records its result and its error, and returns the result or `nil`.
    @discardableResult
    func observe<Value>(_ operation: () async throws -> Value) async -> Value? {
        do {
            let value = try await operation()
            look(value)
            return value
        } catch {
            look(error: error)
            return nil
        }
    }
}

/// Collects `PassportEvent`s.
final class EventLog: PassportObserver, Sendable {
    private let events = Locked<[PassportEvent]>([])
    var all: [PassportEvent] { events.read() }
    func record(_ event: PassportEvent) { events.update { $0.append(event) } }
}

/// Forwards to the fake server and remembers every secret that crossed the wire in either direction.
///
/// While `echo` names request parameters, the token endpoint answers `status` with an OAuth error whose
/// `error_description` repeats the values of those parameters, like a careless server would.
final class SecretHarvest: Sendable {
    struct Echo: Sendable {
        var path: String
        var status: Int
        var code: String
        var parameters: [String]
    }

    private static let secretMembers: Set<String> = [
        "access_token", "refresh_token", "id_token", "device_code", "code", "code_verifier", "client_secret",
        "subject_token", "token", "state",
    ]
    private let secrets = Locked<Set<String>>([])
    private let echo = Locked<Echo?>(nil)
    private let challenges = Locked(false)

    var all: Set<String> { secrets.read() }

    func add(_ secret: String) { secrets.update { _ = $0.insert(secret) } }

    func echoing(_ echo: Echo?) { self.echo.update { $0 = echo } }

    /// While on, the resource answers 401 `insufficient_scope` and repeats the bearer token in the challenge.
    func challenging(_ on: Bool) { challenges.update { $0 = on } }

    func harvest(request: HTTPRequest) {
        let recorded = RecordedRequest(request)
        for (name, value) in recorded.form where Self.secretMembers.contains(name) { add(value) }
        if let header = request.headers["Authorization"] {
            add(header)
            if header.hasPrefix("Bearer ") { add(String(header.dropFirst(7))) }
            if let secret = Self.basicSecret(in: recorded) { add(secret) }
        }
    }

    /// The client secret of an HTTP Basic `Authorization` header.
    static func basicSecret(in request: RecordedRequest) -> String? {
        guard let header = request.headers["Authorization"], header.hasPrefix("Basic "),
            let data = Data(base64Encoded: String(header.dropFirst(6))),
            let text = String(data: data, encoding: .utf8)
        else { return nil }
        return text.split(separator: ":", maxSplits: 1).last.map(String.init)
    }

    func harvest(response: HTTPResponse) {
        guard let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any] else { return }
        for (name, value) in object where Self.secretMembers.contains(name) {
            if let text = value as? String { add(text) }
        }
    }

    /// The scripted answer for `request`, or `nil` to let the server answer.
    func override(for request: RecordedRequest) -> FakeAuthorizationServer.ResponseOverride? {
        if challenges.read(), request.url.host == "api.example.com",
            let token = request.headers["Authorization"]?.dropFirst(7)
        {
            let challenge = #"Bearer error="insufficient_scope", error_description="the token \#(token) lacks scope""#
            return .init(status: 401, headers: ["WWW-Authenticate": challenge])
        }
        guard let echo = echo.read(), request.path == echo.path else { return nil }
        let values = echo.parameters.compactMap {
            $0 == "basic_secret" ? Self.basicSecret(in: request) : request.value($0)
        }
        let description = "The value \(values.joined(separator: " and ")) was not accepted."
        let body = try? JSONSerialization.data(
            withJSONObject: ["error": echo.code, "error_description": description])
        return FakeAuthorizationServer.ResponseOverride(
            status: echo.status, body: body.flatMap { String(data: $0, encoding: .utf8) } ?? "")
    }
}

struct HarvestingTransport: HTTPTransport {
    let server: FakeAuthorizationServer
    let harvest: SecretHarvest

    func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        harvest.harvest(request: request)
        let response = try await server.send(request)
        harvest.harvest(response: response)
        return response
    }
}
