import Foundation
import Testing

@testable import PassportKit

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

struct RedirectPolicyTests {
    private static let headers = [
        "Authorization": "Bearer x", "X-Api-Key": "k", "Cookie": "a=b",
        "Accept": "application/json", "Accept-Language": "en", "User-Agent": "test",
    ]

    private func request(_ url: String, method: String = "GET") -> URLRequest {
        var request = URLRequest(url: URL(string: url)!)
        request.httpMethod = method
        request.allHTTPHeaderFields = Self.headers
        return request
    }

    private func followed(from: String, to: String, method: String = "GET", followsPOST: Bool = false)
        -> URLRequest?
    {
        RedirectPolicy.followed(
            request(to, method: method), from: request(from, method: method), followsPOST: followsPOST)
    }

    private func headerNames(_ request: URLRequest?) -> [String] {
        (request?.allHTTPHeaderFields ?? [:]).keys.map { $0.lowercased() }.sorted()
    }

    @Test("A POST is redirected only when the caller allows it (RFC 6749 §3.2)")
    func postRedirects() {
        #expect(followed(from: "https://as.example.com/token", to: "https://as.example.com/b", method: "POST") == nil)
        #expect(
            followed(
                from: "https://as.example.com/a", to: "https://as.example.com/b", method: "POST", followsPOST: true)
                != nil)
    }

    @Test(arguments: [
        ("https://as.example.com/a", "http://as.example.com/b", false),
        ("https://as.example.com/a", "HTTP://as.example.com/b", false),
        ("https://as.example.com/a", "https://as.example.com/b", true),
        ("http://127.0.0.1:8080/a", "http://127.0.0.1:8080/b", true),
    ])
    func neverLeavesHTTPS(from: String, to: String, isFollowed: Bool) {
        #expect((followed(from: from, to: to) != nil) == isFollowed)
    }

    @Test(arguments: [
        "https://as.example.com/b",
        "https://AS.example.com/b",
        "https://as.example.com:443/b",
    ])
    func keepsEveryHeaderWithinTheOrigin(to: String) {
        #expect(headerNames(followed(from: "https://as.example.com/a", to: to)) == headerNames(request(to)))
    }

    @Test(arguments: [
        ("https://as.example.com/a", "https://other.example.com/b"),
        ("https://as.example.com/a", "https://as.example.com:8443/b"),
        ("http://as.example.com/a", "https://as.example.com/b"),
    ])
    func dropsCredentialsAcrossOrigins(from: String, to: String) {
        #expect(headerNames(followed(from: from, to: to)) == ["accept", "accept-language", "user-agent"])
    }
}
