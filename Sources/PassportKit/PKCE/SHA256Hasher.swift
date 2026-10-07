#if canImport(CryptoKit)
    import CryptoKit
#endif

/// SHA-256 using CryptoKit when available and ``PureSwiftSHA256`` otherwise (ADR 0002).
enum SHA256Hasher {
    static func hash(_ message: [UInt8]) -> [UInt8] {
        #if canImport(CryptoKit)
            Array(CryptoKit.SHA256.hash(data: message))
        #else
            PureSwiftSHA256.hash(message)
        #endif
    }
}
