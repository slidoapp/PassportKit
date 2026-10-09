// Only Apple's URL loading system lets a URLProtocol report a redirect; swift-corelibs-foundation traps on it.
// The redirect rules themselves are covered on every platform by RedirectPolicyTests; these tests check that
// both entry points apply them inside a real URLSession.
#if !canImport(FoundationNetworking)
    import Foundation
    import PassportKitTesting
    import Testing

    @testable import PassportKit

    /// Redirects `/redirect?to=<url>` with a 302 and answers every other path with its request header names.
    final class RedirectingURLProtocol: URLProtocol {
        override class func canInit(with request: URLRequest) -> Bool { true }
        override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

        override func startLoading() {
            guard let url = request.url, let client else { return }
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false)
            if url.path == "/redirect", let to = components?.queryItems?.first(where: { $0.name == "to" })?.value,
                let target = URL(string: to)
            {
                let redirect = HTTPURLResponse(
                    url: url, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: ["Location": to])!
                var next = request
                next.url = target
                client.urlProtocol(self, wasRedirectedTo: next, redirectResponse: redirect)
                return
            }
            let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1", headerFields: [:])!
            let names = (request.allHTTPHeaderFields ?? [:]).keys.map { $0.lowercased() }.sorted()
            client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client.urlProtocol(self, didLoad: Data(names.joined(separator: ",").utf8))
            client.urlProtocolDidFinishLoading(self)
        }

        override func stopLoading() {}
    }

    struct URLSessionRedirectTests {
        private static func configuration() -> URLSessionConfiguration {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.protocolClasses = [RedirectingURLProtocol.self]
            return configuration
        }

        private static func redirect(to target: String) -> URL {
            URL(string: "https://as.example.com/redirect?to=\(target)")!
        }

        @Test(arguments: [
            ("https://as.example.com/echo", "accept,authorization,x-api-key"),
            ("https://other.example.com/echo", "accept"),
        ])
        func transportAppliesThePolicy(target: String, headerNames: String) async throws {
            let transport = URLSessionTransport(configuration: Self.configuration())
            let response = try await transport.send(
                HTTPRequest(
                    method: .get, url: Self.redirect(to: target),
                    headers: ["Authorization": "Bearer x", "X-Api-Key": "k", "Accept": "application/json"]))
            #expect(response.statusCode == 200)
            #expect(String(decoding: response.body, as: UTF8.self) == headerNames)
        }

        @Test("data(for:session:) does not let the token follow a cross-origin redirect")
        func authorizerAppliesThePolicy() async throws {
            let session = URLSession(configuration: Self.configuration())
            defer { session.invalidateAndCancel() }
            let manager = TokenManager(
                client: try ClientFixtures.client(RecordingTransport()), store: InMemoryCredentialStore(),
                account: CredentialAccount(service: "unit", account: "user"))
            try await manager.signIn(
                with: TokenResponse(accessToken: Secret("opaque"), tokenType: "Bearer", expiresIn: .seconds(3600)))
            let authorizer = RequestAuthorizer(manager: manager)
            let (body, response) = try await authorizer.data(
                for: URLRequest(url: Self.redirect(to: "https://other.example.com/echo")), session: session)
            #expect(response.url?.host == "other.example.com")
            #expect(!String(decoding: body, as: UTF8.self).contains("authorization"))
        }
    }
#endif
