import Foundation
import Testing

@testable import PassportKit

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Serves canned responses chosen by URL path, so tests need no network and no shared state.
final class StubURLProtocol: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url, let client else { return }
        func respond(_ status: Int, _ headers: [String: String] = [:]) {
            let response = HTTPURLResponse(
                url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers)!
            client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        }
        switch url.path {
        case "/ok":
            respond(200, ["Content-Type": "application/json", "X-Echo-Method": request.httpMethod ?? ""])
            client.urlProtocol(self, didLoad: Data(#"{"ok":true}"#.utf8))
            client.urlProtocolDidFinishLoading(self)
        case "/big":
            respond(200)
            for _ in 0..<3 { client.urlProtocol(self, didLoad: Data(count: 600 * 1_024)) }
            client.urlProtocolDidFinishLoading(self)
        case "/declared":
            respond(200, ["Content-Length": "5000000"])
            client.urlProtocol(self, didLoad: Data(count: 10))
            client.urlProtocolDidFinishLoading(self)
        case "/exact":
            respond(200)
            client.urlProtocol(self, didLoad: Data(count: URLSessionTransport.maximumBodySize))
            client.urlProtocolDidFinishLoading(self)
        case "/fail":
            client.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet))
        default:
            break  // never answers; used to test cancellation
        }
    }

    override func stopLoading() {}
}

struct URLSessionTransportTests {
    private let transport: URLSessionTransport

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [StubURLProtocol.self]
        transport = URLSessionTransport(configuration: configuration)
    }

    private func request(_ path: String, method: HTTPMethod = .post, headers: HTTPHeaders = [:]) -> HTTPRequest {
        HTTPRequest(
            method: method, url: URL(string: "https://as.example.com\(path)")!, headers: headers, body: Data("a=b".utf8)
        )
    }

    @Test func returnsStatusHeadersAndBody() async throws {
        let response = try await transport.send(request("/ok"))
        #expect(response.statusCode == 200)
        #expect(response.headers["content-type"] == "application/json")
        #expect(response.headers["X-Echo-Method"] == "POST")
        #expect(String(data: response.body, encoding: .utf8) == #"{"ok":true}"#)
    }

    @Test func acceptsBodyAtTheLimit() async throws {
        let response = try await transport.send(request("/exact"))
        #expect(response.body.count == URLSessionTransport.maximumBodySize)
    }

    @Test(arguments: ["/big", "/declared"])
    func rejectsBodiesOverOneMebibyte(path: String) async {
        await #expect {
            try await transport.send(request(path))
        } throws: { error in
            (error as? PassportError)?.code == .invalidResponse
        }
    }

    @Test func appliesDefaultAndConfiguredTimeouts() {
        #expect(transport.sessionConfiguration.timeoutIntervalForRequest == 30)
        #expect(transport.sessionConfiguration.timeoutIntervalForResource == 60)
        let custom = URLSessionTransport(requestTimeout: .seconds(5), resourceTimeout: .milliseconds(1500))
        #expect(custom.sessionConfiguration.timeoutIntervalForRequest == 5)
        #expect(custom.sessionConfiguration.timeoutIntervalForResource == 1.5)
    }

    @Test func aCompleteResponseSurvivesALateCancellation() async throws {
        let delegate = URLSessionTransportDelegate(bodyLimit: 100)
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let url = URL(string: "https://as.example.com/ok")!
        let task = session.dataTask(with: URLRequest(url: url))
        let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        let result = await withCheckedContinuation { (outer: CheckedContinuation<HTTPResponse?, Never>) in
            Task {
                do {
                    let value = try await withCheckedThrowingContinuation { continuation in
                        delegate.register(task: task, continuation: continuation)
                        delegate.urlSession(session, dataTask: task, didReceive: response) { _ in }
                        delegate.urlSession(session, dataTask: task, didReceive: Data("rotated".utf8))
                        delegate.cancel(identifier: task.taskIdentifier)
                        delegate.urlSession(session, task: task, didCompleteWithError: nil)
                    }
                    outer.resume(returning: value)
                } catch {
                    outer.resume(returning: nil)
                }
            }
        }
        #expect(String(data: try #require(result).body, encoding: .utf8) == "rotated")
    }

    @Test func mapsTransportErrorsKeepingTheUnderlyingError() async {
        await #expect {
            try await transport.send(request("/fail"))
        } throws: { error in
            guard let error = error as? PassportError else { return false }
            return error.code == .transportFailure && error.recovery == .retryLater(after: nil)
                && (error.underlying as? URLError)?.code == .notConnectedToInternet
        }
    }

    @Test func cancellationPropagatesUnwrapped() async {
        let transport = transport
        let request = request("/hang")
        let task = Task { try await transport.send(request) }
        task.cancel()
        await #expect(throws: CancellationError.self) {
            try await task.value
        }
    }
}
