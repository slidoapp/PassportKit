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
        case "/echo":
            respond(200)
            client.urlProtocol(
                self, didLoad: Data("\(request.value(forHTTPHeaderField: "Authorization") ?? "none")".utf8))
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
        case "/redirect":
            let target = URL(string: "https://as.example.com/ok")!
            let redirect = HTTPURLResponse(
                url: url, statusCode: 307, httpVersion: "HTTP/1.1", headerFields: ["Location": target.absoluteString])!
            var next = URLRequest(url: target)
            next.httpMethod = request.httpMethod
            next.allHTTPHeaderFields = request.allHTTPHeaderFields
            client.urlProtocol(self, wasRedirectedTo: next, redirectResponse: redirect)
        case "/other-host-echo":
            let target = URL(string: "https://other.example.com/echo")!
            let redirect = HTTPURLResponse(
                url: url, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: ["Location": target.absoluteString])!
            var next = URLRequest(url: target)
            next.httpMethod = request.httpMethod
            next.allHTTPHeaderFields = request.allHTTPHeaderFields
            client.urlProtocol(self, wasRedirectedTo: next, redirectResponse: redirect)
        case "/fail":
            client.urlProtocol(self, didFailWithError: URLError(.notConnectedToInternet))
        default:
            break  // never answers; used to test cancellation
        }
    }

    override func stopLoading() {}
}

/// Captures the redirect decision the delegate makes synchronously.
final class RedirectOutcome: @unchecked Sendable {
    // Safe: the delegate invokes the completion handler synchronously on the calling thread.
    private(set) var request: URLRequest?
    func record(_ request: URLRequest?) { self.request = request }
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

    // URLProtocol stubs cannot deliver an unfollowed redirect response, so the policy is checked on the delegate.
    @Test func doesNotFollowPostRedirects() {
        let delegate = URLSessionTransportDelegate(bodyLimit: 10)
        let session = URLSession(configuration: .ephemeral)
        defer { session.invalidateAndCancel() }
        let target = URL(string: "https://as.example.com/ok")!
        let redirect = HTTPURLResponse(url: target, statusCode: 307, httpVersion: nil, headerFields: nil)!
        for (method, followed) in [("POST", false), ("GET", true)] {
            var original = URLRequest(url: target)
            original.httpMethod = method
            let task = session.dataTask(with: original)
            let outcome = RedirectOutcome()
            delegate.urlSession(session, task: task, willPerformHTTPRedirection: redirect, newRequest: original) {
                outcome.record($0)
            }
            #expect((outcome.request != nil) == followed)
        }
    }

    @Test func followsGetRedirects() async throws {
        let response = try await transport.send(request("/redirect", method: .get))
        #expect(response.statusCode == 200)
    }

    @Test func dropsAuthorizationWhenRedirectedToAnotherHost() async throws {
        let response = try await transport.send(
            request("/other-host-echo", method: .get, headers: ["Authorization": "Bearer \(Canary.value)"])
        )
        #expect(String(data: response.body, encoding: .utf8) == "none")
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
