import Foundation
import Logging

/// Log metadata keys.
enum LogKey {
    static let endpoint = "endpoint"
    static let grantType = "grant_type"
    static let status = "status"
    static let errorCode = "error_code"
    static let durationMilliseconds = "duration_ms"
    static let reason = "reason"
    static let operation = "operation"
    static let derivation = "derivation"
    static let revoke = "revoke"
    static let port = "port"
}

extension Duration {
    /// Whole milliseconds, for log metadata.
    var wholeMilliseconds: Int {
        let (seconds, attoseconds) = components
        return Int(seconds) * 1000 + Int(attoseconds / 1_000_000_000_000_000)
    }
}

extension Logger.Metadata {
    /// The metadata of one request to an authorization server endpoint: never a URL, header or body.
    static func request(
        endpoint: EndpointKind, grantType: GrantType? = nil, status: Int? = nil, errorCode: String? = nil,
        duration: Duration? = nil
    ) -> Logger.Metadata {
        var metadata: Logger.Metadata = [LogKey.endpoint: "\(endpoint.rawValue)"]
        if let grantType { metadata[LogKey.grantType] = "\(grantType.rawValue)" }
        if let status { metadata[LogKey.status] = "\(status)" }
        if let errorCode { metadata[LogKey.errorCode] = "\(errorCode)" }
        if let duration { metadata[LogKey.durationMilliseconds] = "\(duration.wholeMilliseconds)" }
        return metadata
    }
}

extension Error {
    /// Whether the failure is an expected loss of connectivity (offline, no route, timeout) rather than a fault
    /// worth reporting, such as a TLS or certificate failure. Classifies on the underlying `URLError`, looking
    /// through ``PassportError`` wrappers.
    var isConnectivityFailure: Bool {
        if let error = self as? PassportError { return error.underlying?.isConnectivityFailure ?? false }
        guard let error = self as? URLError else { return false }
        switch error.code {
        case .notConnectedToInternet, .networkConnectionLost, .timedOut, .cannotFindHost, .cannotConnectToHost,
            .dnsLookupFailed, .dataNotAllowed, .internationalRoamingOff, .callIsActive:
            return true
        default: return false
        }
    }
}

extension Logger.Level {
    /// `.notice` for an expected loss of connectivity, `.warning` for any other failure.
    static func level(forTransportFailure error: any Error) -> Logger.Level {
        error.isConnectivityFailure ? .notice : .warning
    }
}
