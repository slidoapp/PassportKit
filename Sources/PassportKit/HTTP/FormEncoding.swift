import Foundation

/// `application/x-www-form-urlencoded` encoding as profiled by RFC 6749 Appendix B.
///
/// UTF-8; every byte except the unreserved characters `A-Z a-z 0-9 - . _ ~` is percent-encoded
/// with uppercase hex; space becomes `+` and a literal `+` becomes `%2B`.
package enum FormEncoding {
    /// Encodes one name or value.
    package static func encodeComponent(_ text: String) -> String {
        var result = ""
        for byte in text.utf8 {
            switch byte {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"),
                UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"),
                UInt8(ascii: "~"):
                result.unicodeScalars.append(Unicode.Scalar(byte))
            case UInt8(ascii: " "):
                result += "+"
            default:
                result += "%" + hexDigits[Int(byte >> 4)] + hexDigits[Int(byte & 0x0F)]
            }
        }
        return result
    }

    /// Encodes pairs as `name=value` joined by `&`, preserving order and repeats.
    package static func encode(_ parameters: [(String, String)]) -> Data {
        let text = parameters.map { encodeComponent($0.0) + "=" + encodeComponent($0.1) }.joined(separator: "&")
        return Data(text.utf8)
    }

    /// Decodes a form body into ordered pairs, or `nil` when it is not valid UTF-8 or percent-encoding.
    ///
    /// Intended for tests and fake servers. Empty segments are skipped; a segment without `=` has an empty value.
    package static func decode(_ data: Data) -> [(String, String)]? {
        guard let text = String(data: data, encoding: .utf8) else { return nil }
        var pairs: [(String, String)] = []
        for segment in text.split(separator: "&", omittingEmptySubsequences: true) {
            let parts = segment.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard let name = decodeComponent(String(parts[0])) else { return nil }
            guard let value = decodeComponent(parts.count > 1 ? String(parts[1]) : "") else { return nil }
            pairs.append((name, value))
        }
        return pairs
    }

    private static let hexDigits = Array("0123456789ABCDEF").map(String.init)

    private static func decodeComponent(_ text: String) -> String? {
        var bytes: [UInt8] = []
        var iterator = text.utf8.makeIterator()
        while let byte = iterator.next() {
            switch byte {
            case UInt8(ascii: "+"):
                bytes.append(UInt8(ascii: " "))
            case UInt8(ascii: "%"):
                guard let high = iterator.next().flatMap(hexValue), let low = iterator.next().flatMap(hexValue) else {
                    return nil
                }
                bytes.append(high << 4 | low)
            default:
                bytes.append(byte)
            }
        }
        return String(bytes: bytes, encoding: .utf8)
    }

    private static func hexValue(_ byte: UInt8) -> UInt8? {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): byte - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): byte - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): byte - UInt8(ascii: "A") + 10
        default: nil
        }
    }
}
