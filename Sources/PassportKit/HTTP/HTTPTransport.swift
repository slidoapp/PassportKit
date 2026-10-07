/// Sends HTTP requests on behalf of the library. The default is ``URLSessionTransport``.
public protocol HTTPTransport: Sendable {
    /// Sends `request` and returns the response.
    ///
    /// Throws only for transport failures; any HTTP status is a normal response. Implementations
    /// must not follow redirects for `POST` and must let `CancellationError` propagate unchanged.
    func send(_ request: HTTPRequest) async throws -> HTTPResponse
}
