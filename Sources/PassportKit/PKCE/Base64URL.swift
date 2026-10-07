/// Base64url without padding (RFC 4648 §5), as PKCE and `state` values require.
enum Base64URL {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

    static func encode(_ bytes: [UInt8]) -> String {
        var output = ""
        var index = 0
        while index < bytes.count {
            let remaining = bytes.count - index
            let first = Int(bytes[index])
            let second = remaining > 1 ? Int(bytes[index + 1]) : 0
            let third = remaining > 2 ? Int(bytes[index + 2]) : 0
            let combined = first << 16 | second << 8 | third
            output.append(alphabet[combined >> 18 & 63])
            output.append(alphabet[combined >> 12 & 63])
            if remaining > 1 { output.append(alphabet[combined >> 6 & 63]) }
            if remaining > 2 { output.append(alphabet[combined & 63]) }
            index += 3
        }
        return output
    }
}
