import Foundation
import HTTPTypes
import HTTPTypesFoundation

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Collects responses for ``URLSessionTransport`` with a streaming body cap and redirect policy.
// Safe: every mutable member is only touched while holding `lock`.
final class URLSessionTransportDelegate: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private struct Pending {
        var task: URLSessionTask
        var continuation: CheckedContinuation<(HTTPResponse, Data), any Error>
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

    func register(task: URLSessionTask, continuation: CheckedContinuation<(HTTPResponse, Data), any Error>) {
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

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(RedirectPolicy.followed(request, from: task.originalRequest, followsPOST: false))
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
                throwing: PassportError(.invalidResponse, detail: "Response body exceeds the size limit.")
            )
        } else if error == nil, let response = entry.response?.httpResponse {
            // A complete response wins over a late cancellation: a rotated refresh token must not be lost.
            entry.continuation.resume(returning: (response, entry.body))
        } else if entry.cancelledByCaller {
            entry.continuation.resume(throwing: CancellationError())
        } else if let error {
            entry.continuation.resume(
                throwing: PassportError(.transportFailure, detail: "The request failed.", underlying: error)
            )
        } else {
            entry.continuation.resume(
                throwing: PassportError(.invalidResponse, detail: "The response was not an HTTP response.")
            )
        }
    }
}
