import Logging

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
        var metadata: Logger.Metadata = ["endpoint": "\(endpoint.rawValue)"]
        if let grantType { metadata["grant_type"] = "\(grantType.rawValue)" }
        if let status { metadata["status"] = "\(status)" }
        if let errorCode { metadata["error_code"] = "\(errorCode)" }
        if let duration { metadata["duration_ms"] = "\(duration.wholeMilliseconds)" }
        return metadata
    }
}
