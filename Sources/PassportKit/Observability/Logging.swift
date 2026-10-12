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
