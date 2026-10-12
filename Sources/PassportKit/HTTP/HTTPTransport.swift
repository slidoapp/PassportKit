import Foundation
import HTTPTypes

/// Sends HTTP requests on behalf of the library. The default is ``URLSessionTransport``.
///
/// The currency types are `HTTPTypes.HTTPRequest` and `HTTPTypes.HTTPResponse` from swift-http-types; the
/// body travels beside the request as `Data`, the way swift-openapi-runtime's `ClientTransport` separates
/// them. Import `HTTPTypes` to implement or call a transport.
public protocol HTTPTransport: Sendable {
    /// Sends `request` with `body` and returns the response and its body.
    ///
    /// `request` carries an absolute URL (`HTTPRequest(method:url:headerFields:)`). Throws only for transport
    /// failures; any HTTP status is a normal response. Implementations must not follow redirects for `POST`
    /// and must let `CancellationError` propagate unchanged.
    ///
    /// Header fields can carry credentials, and `HTTPTypes` prints them: never log `request`, `HTTPFields` or
    /// a response from inside a transport.
    func send(_ request: HTTPRequest, body: Data?) async throws -> (HTTPResponse, Data)
}
