import Logging

/// Log metadata keys, shared by the library modules.
package enum LogKey {
    package static let endpoint = "endpoint"
    package static let grantType = "grant_type"
    package static let status = "status"
    package static let errorCode = "error_code"
    package static let durationMilliseconds = "duration_ms"
    package static let reason = "reason"
    package static let operation = "operation"
    package static let derivation = "derivation"
    package static let revoke = "revoke"
    package static let port = "port"
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
