import Foundation

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Which redirects a request that may carry credentials follows. Shared by ``URLSessionTransport`` and
/// ``RequestAuthorizer/data(for:target:session:)``.
enum RedirectPolicy {
    /// Request headers that carry no credential and stay on a cross-origin redirect.
    private static let retainedAcrossOrigins: Set<String> = ["accept", "accept-language", "user-agent"]

    /// The request to send after a redirect, or `nil` to stop and deliver the redirect response.
    ///
    /// A `POST` is not redirected unless `followsPOST` (token endpoints must not redirect, RFC 6749 §3.2), a
    /// redirect never leaves HTTPS for HTTP, and a redirect to another scheme, host or port drops every header
    /// except a small set that carries no credential.
    static func followed(_ request: URLRequest, from original: URLRequest?, followsPOST: Bool) -> URLRequest? {
        if !followsPOST, original?.httpMethod?.uppercased() == "POST" { return nil }
        var redirected = request
        if let from = original?.url, let target = request.url {
            if from.scheme?.lowercased() == "https", target.scheme?.lowercased() != "https" { return nil }
            if !isSameOrigin(from, target) {
                for name in (redirected.allHTTPHeaderFields ?? [:]).keys
                where !retainedAcrossOrigins.contains(name.lowercased()) {
                    redirected.setValue(nil, forHTTPHeaderField: name)
                }
            }
        }
        return redirected
    }

    private static func isSameOrigin(_ left: URL, _ right: URL) -> Bool {
        OriginKey(left) == OriginKey(right)
    }
}

/// The scheme, host and port of a URL, compared the way browsers compare origins.
struct OriginKey: Hashable {
    var scheme: String?
    var host: String?
    var port: Int

    init(_ url: URL) {
        let scheme = url.scheme?.lowercased()
        self.scheme = scheme
        host = url.host?.lowercased()
        port = url.port ?? (scheme == "https" ? 443 : 80)
    }
}

/// Applies ``RedirectPolicy`` to one task of a caller's `URLSession`.
final class RedirectPolicyDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(RedirectPolicy.followed(request, from: task.originalRequest, followsPOST: true))
    }
}
