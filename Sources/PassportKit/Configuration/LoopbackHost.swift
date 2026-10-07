/// Loopback host rule for plain `http` (RFC 8252 §7.3, §8.3).
enum LoopbackHost {
    /// Whether `host` is `localhost`, `127.0.0.1` or `::1` (with or without brackets), case-insensitive.
    static func isLoopback(_ host: String?) -> Bool {
        guard let host = host?.lowercased() else { return false }
        return ["localhost", "127.0.0.1", "::1", "[::1]"].contains(host)
    }
}
