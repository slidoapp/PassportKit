import Foundation

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// The default ``HTTPTransport``, built on `URLSession`.
///
/// - Uses an ephemeral configuration by default, with cookies and the URL cache disabled.
/// - Never follows redirects for `POST` (RFC 6749 §3.2: token endpoints must not redirect). Other
///   redirects are followed unless they leave HTTPS for HTTP; `Authorization` is dropped when the host changes.
/// - Caps response bodies at 1 MiB; a larger body fails with ``PassportError/Code-swift.struct/invalidResponse``.
/// - Reports transport errors as ``PassportError/Code-swift.struct/transportFailure`` with the underlying error.
public struct URLSessionTransport: HTTPTransport {
    /// The largest accepted response body, in bytes.
    public static let maximumBodySize = 1_048_576

    private let session: SessionOwner

    /// Creates a transport from `configuration`.
    ///
    /// The configuration is copied; cookie handling and the URL cache are disabled on the copy.
    public init(configuration: URLSessionConfiguration = .ephemeral) {
        let copy = (configuration.copy() as? URLSessionConfiguration) ?? configuration
        copy.httpCookieStorage = nil
        copy.httpShouldSetCookies = false
        copy.urlCache = nil
        copy.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = SessionOwner(configuration: copy, bodyLimit: Self.maximumBodySize)
    }

    /// Sends `request`. Cancelling the calling task cancels the request and throws `CancellationError`.
    public func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        var urlRequest = URLRequest(url: request.url)
        urlRequest.httpMethod = request.method.rawValue
        urlRequest.httpBody = request.body
        urlRequest.httpShouldHandleCookies = false
        for (name, value) in request.headers {
            urlRequest.addValue(value, forHTTPHeaderField: name)
        }
        let task = session.session.dataTask(with: urlRequest)
        let identifier = task.taskIdentifier
        let delegate = session.delegate
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                delegate.register(task: task, continuation: continuation)
                task.resume()
                if Task.isCancelled {
                    delegate.cancel(identifier: identifier)
                }
            }
        } onCancel: {
            delegate.cancel(identifier: identifier)
        }
    }
}

/// Owns the session and invalidates it on release, which breaks the session-to-delegate reference cycle.
private final class SessionOwner: Sendable {
    let session: URLSession
    let delegate: URLSessionTransportDelegate

    init(configuration: URLSessionConfiguration, bodyLimit: Int) {
        delegate = URLSessionTransportDelegate(bodyLimit: bodyLimit)
        session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
    }

    deinit {
        session.finishTasksAndInvalidate()
    }
}
