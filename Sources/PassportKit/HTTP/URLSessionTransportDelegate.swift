import Foundation

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Collects responses for ``URLSessionTransport`` with a streaming body cap and redirect policy.
// Safe: every mutable member is only touched while holding `lock`.
final class URLSessionTransportDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private struct Pending {
        var task: URLSessionTask
        var continuation: CheckedContinuation<HTTPResponse, any Error>
        var response: HTTPURLResponse?
        var body = Data()
        var exceededLimit = false
        var cancelledByCaller = false
    }

    private let bodyLimit: Int
    private let lock = NSLock()
    private var pending: [Int: Pending] = [:]

    init(bodyLimit: Int) {
        self.bodyLimit = bodyLimit
    }

    func register(task: URLSessionTask, continuation: CheckedContinuation<HTTPResponse, any Error>) {
        lock.withLock {
            pending[task.taskIdentifier] = Pending(task: task, continuation: continuation)
        }
    }

    func cancel(identifier: Int) {
        let task = lock.withLock { () -> URLSessionTask? in
            pending[identifier]?.cancelledByCaller = true
            return pending[identifier]?.task
        }
        task?.cancel()
    }

    /// Request headers that carry no credential and stay on a cross-origin redirect.
    private static let retainedAcrossOrigins: Set<String> = ["accept", "accept-language", "user-agent"]

    private static func isSameOrigin(_ left: URL, _ right: URL) -> Bool {
        func origin(_ url: URL) -> [String?] {
            let scheme = url.scheme?.lowercased()
            return [scheme, url.host?.lowercased(), String(url.port ?? (scheme == "https" ? 443 : 80))]
        }
        return origin(left) == origin(right)
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        let original = task.originalRequest
        if original?.httpMethod?.uppercased() == "POST" {
            completionHandler(nil)
            return
        }
        var redirected = request
        if let from = original?.url, let target = request.url {
            if from.scheme?.lowercased() == "https", target.scheme?.lowercased() != "https" {
                completionHandler(nil)
                return
            }
            if !Self.isSameOrigin(from, target) {
                for name in (redirected.allHTTPHeaderFields ?? [:]).keys
                where !Self.retainedAcrossOrigins.contains(name.lowercased()) {
                    redirected.setValue(nil, forHTTPHeaderField: name)
                }
            }
        }
        completionHandler(redirected)
    }

    func urlSession(
        _ session: URLSession,
        dataTask: URLSessionDataTask,
        didReceive response: URLResponse,
        completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void
    ) {
        let exceeded = response.expectedContentLength > Int64(bodyLimit)
        lock.withLock {
            pending[dataTask.taskIdentifier]?.response = response as? HTTPURLResponse
            if exceeded { pending[dataTask.taskIdentifier]?.exceededLimit = true }
        }
        completionHandler(exceeded ? .cancel : .allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let exceeded = lock.withLock { () -> Bool in
            guard var entry = pending[dataTask.taskIdentifier] else { return false }
            entry.body.append(data)
            entry.exceededLimit = entry.exceededLimit || entry.body.count > bodyLimit
            if entry.exceededLimit { entry.body = Data() }
            pending[dataTask.taskIdentifier] = entry
            return entry.exceededLimit
        }
        if exceeded { dataTask.cancel() }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        guard let entry = lock.withLock({ pending.removeValue(forKey: task.taskIdentifier) }) else { return }
        if entry.exceededLimit {
            entry.continuation.resume(
                throwing: PassportError(.invalidResponse, errorDescription: "Response body exceeds the size limit.")
            )
        } else if error == nil, let response = entry.response {
            // A complete response wins over a late cancellation: a rotated refresh token must not be lost.
            entry.continuation.resume(
                returning: HTTPResponse(
                    statusCode: response.statusCode,
                    headers: Self.headers(from: response),
                    body: entry.body
                )
            )
        } else if entry.cancelledByCaller {
            entry.continuation.resume(throwing: CancellationError())
        } else if let error {
            entry.continuation.resume(
                throwing: PassportError(.transportFailure, errorDescription: "The request failed.", underlying: error)
            )
        } else {
            entry.continuation.resume(
                throwing: PassportError(.invalidResponse, errorDescription: "The response was not an HTTP response.")
            )
        }
    }

    // `allHeaderFields` is unordered and merges repeated lines with ", ", so sort for determinism.
    private static func headers(from response: HTTPURLResponse) -> HTTPHeaders {
        var headers = HTTPHeaders()
        let fields = response.allHeaderFields.compactMap { key, value -> (String, String)? in
            guard let name = key as? String, let text = value as? String else { return nil }
            return (name, text)
        }
        for (name, value) in fields.sorted(by: { $0.0 < $1.0 }) {
            headers.add(name: name, value: value)
        }
        return headers
    }
}
