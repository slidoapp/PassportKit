import CryptoKit

/// The S256 code challenge transformation (RFC 7636 §4.2), computed with CryptoKit and its own base64url
/// encoder rather than the library's code path, so the fake verifies the client rather than echoing it.
enum PKCEChallenge {
    static func s256(_ verifier: String) -> String {
        base64URL(Array(SHA256.hash(data: Array(verifier.utf8))))
    }

    private static func base64URL(_ bytes: [UInt8]) -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        var output = ""
        for start in stride(from: 0, to: bytes.count, by: 3) {
            let chunk = Array(bytes[start..<min(start + 3, bytes.count)])
            let combined = chunk.enumerated().reduce(0) { $0 | Int($1.element) << (16 - 8 * $1.offset) }
            for index in 0...chunk.count { output.append(alphabet[combined >> (18 - 6 * index) & 63]) }
        }
        return output
    }
}
