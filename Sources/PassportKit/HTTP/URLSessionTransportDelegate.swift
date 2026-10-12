import Foundation
import HTTPTypes
import HTTPTypesFoundation
import os

/// Collects responses for ``URLSessionTransport`` with a streaming body cap and redirect policy.
final class URLSessionTransportDelegate: NSObject, URLSessionDataDelegate, Sendable {
    private struct Pending {
        var task: URLSessionTask
        var continuation: CheckedContinuation<(HTTPResponse, Data), any Error>
        var response: HTTPURLResponse?
        var body = Data()
        var exceededLimit = false
        var cancelledByCaller = false
    }

    private let bodyLimit: Int
    private let pending = OSAllocatedUnfairLock(initialState: [Int: Pending]())

    init(bodyLimit: Int) {
        self.bodyLimit = bodyLimit
    }

    func register(task: URLSessionTask, continuation: CheckedContinuation<(HTTPResponse, Data), any Error>) {
        pending.withLock { $0[task.taskIdentifier] = Pending(task: task, continuation: continuation) }
    }

    func cancel(identifier: Int) {
        let task = pending.withLock { entries -> URLSessionTask? in
            entries[identifier]?.cancelledByCaller = true
            return entries[identifier]?.task
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
        pending.withLock { entries in
            entries[dataTask.taskIdentifier]?.response = response as? HTTPURLResponse
            if exceeded { entries[dataTask.taskIdentifier]?.exceededLimit = true }
        }
        completionHandler(exceeded ? .cancel : .allow)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let limit = bodyLimit
        let exceeded = pending.withLock { entries -> Bool in
            guard var entry = entries[dataTask.taskIdentifier] else { return false }
            entry.body.append(data)
            entry.exceededLimit = entry.exceededLimit || entry.body.count > limit
            if entry.exceededLimit { entry.body = Data() }
            entries[dataTask.taskIdentifier] = entry
            return entry.exceededLimit
        }
        if exceeded { dataTask.cancel() }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        guard let entry = pending.withLock({ $0.removeValue(forKey: task.taskIdentifier) }) else { return }
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
