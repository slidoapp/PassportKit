import Foundation

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// The default ``HTTPTransport``, built on `URLSession`.
///
/// - Uses an ephemeral configuration by default, with cookies and the URL cache disabled.
/// - Gives up on a request after 30 seconds without progress and on the whole exchange after 60 seconds
///   (configurable), so a stalled server cannot hang a refresh or a device poll.
/// - Never follows redirects for `POST` (RFC 6749 §3.2: token endpoints must not redirect). Other
///   redirects are followed unless they leave HTTPS for HTTP. When a redirect changes scheme, host or port, every
///   request header except a small set of standard ones is dropped, so credentials never travel to another origin.
/// - Caps response bodies at 1 MiB; a larger body fails with ``PassportError/Code-swift.struct/invalidResponse``.
/// - Reports transport errors as ``PassportError/Code-swift.struct/transportFailure`` with the underlying error.
public struct URLSessionTransport: HTTPTransport {
    /// The largest accepted response body, in bytes.
    static let maximumBodySize = 1_048_576

    private let session: SessionOwner

    /// The effective session configuration, for tests.
    var sessionConfiguration: URLSessionConfiguration { session.session.configuration }

    /// Creates a transport from `configuration`.
    ///
    /// The configuration is copied; cookie handling and the URL cache are disabled on the copy, and the
    /// timeouts are set from `requestTimeout` (`timeoutIntervalForRequest`, the longest silence) and
    /// `resourceTimeout` (`timeoutIntervalForResource`, the longest total time of one request).
    public init(
        configuration: URLSessionConfiguration = .ephemeral,
        requestTimeout: Duration = .seconds(30),
        resourceTimeout: Duration = .seconds(60)
    ) {
        let copy = (configuration.copy() as? URLSessionConfiguration) ?? configuration
        copy.timeoutIntervalForRequest = requestTimeout.timeInterval
        copy.timeoutIntervalForResource = resourceTimeout.timeInterval
        copy.httpCookieStorage = nil
        copy.httpShouldSetCookies = false
        copy.urlCache = nil
        copy.requestCachePolicy = .reloadIgnoringLocalCacheData
        session = SessionOwner(configuration: copy, bodyLimit: Self.maximumBodySize)
    }

    /// Sends `request`. Cancelling the calling task cancels the request and throws `CancellationError`, unless the
    /// complete response had already arrived: it is returned then, so a rotated refresh token is never lost.
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

extension Duration {
    fileprivate var timeInterval: TimeInterval {
        Double(components.seconds) + Double(components.attoseconds) / 1e18
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
