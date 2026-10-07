import Foundation

/// The request line and headers of an HTTP/1.x request, as read by the loopback listener.
///
/// This is a deliberately small parser: it accepts only what a browser sends for a redirect (an
/// origin-form target and plain header lines) and treats everything else as malformed.
struct LoopbackRequestHead: Equatable {
    /// The most bytes read before the head must be complete (RFC 9112 §3 leaves the limit to the recipient).
    static let maximumSize = 8 * 1024

    enum Outcome: Equatable {
        /// The head has not ended yet; read more.
        case incomplete
        /// No complete head within ``maximumSize`` bytes.
        case tooLarge
        case malformed
        case complete(LoopbackRequestHead)
    }

    var method: String
    /// The origin-form request target, such as `/callback?code=abc`.
    var target: String
    /// Header values by lowercased name. A repeated name makes the request malformed.
    var headers: [String: String]

    /// The target without its query.
    var path: String {
        String(target.prefix { $0 != "?" })
    }

    /// Parses the bytes received so far (RFC 9112 §3, §5).
    static func parse(_ data: Data) -> Outcome {
        let bytes = [UInt8](data.prefix(maximumSize + 4))
        guard let end = headEnd(in: bytes) else {
            return data.count >= maximumSize ? .tooLarge : .incomplete
        }
        guard end <= maximumSize else { return .tooLarge }
        guard bytes[..<end].allSatisfy({ $0 == 0x09 || $0 == 0x0D || $0 == 0x0A || ($0 >= 0x20 && $0 < 0x7F) }),
            let text = String(bytes: bytes[..<end], encoding: .ascii)
        else { return .malformed }
        // Lines end with CRLF only; a bare CR or LF inside a line is malformed.
        let lines = text.components(separatedBy: "\r\n").dropLast(2)
        guard let requestLine = lines.first, !lines.contains(where: { $0.contains("\r") || $0.contains("\n") }) else {
            return .malformed
        }
        let parts = requestLine.split(separator: " ", omittingEmptySubsequences: false)
        guard parts.count == 3, !parts[0].isEmpty, parts[0].allSatisfy(isTokenCharacter),
            parts[1].hasPrefix("/"), !parts[1].contains("#"), parts[2] == "HTTP/1.1" || parts[2] == "HTTP/1.0"
        else { return .malformed }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            // A line starting with whitespace is obsolete line folding (RFC 9112 §5.2): its name is invalid.
            guard let colon = line.firstIndex(of: ":"), colon != line.startIndex else { return .malformed }
            let name = line[..<colon]
            guard name.allSatisfy(isTokenCharacter) else { return .malformed }
            let key = name.lowercased()
            guard headers[key] == nil else { return .malformed }
            headers[key] = line[line.index(after: colon)...].trimmingCharacters(in: CharacterSet(charactersIn: " \t"))
        }
        return .complete(LoopbackRequestHead(method: String(parts[0]), target: String(parts[1]), headers: headers))
    }

    /// The index just past the blank line that ends the head, if present.
    private static func headEnd(in bytes: [UInt8]) -> Int? {
        guard bytes.count >= 4 else { return nil }
        for index in 0...(bytes.count - 4)
        where bytes[index] == 0x0D && bytes[index + 1] == 0x0A && bytes[index + 2] == 0x0D && bytes[index + 3] == 0x0A {
            return index + 4
        }
        return nil
    }

    /// `tchar` from RFC 9110 §5.6.2.
    private static func isTokenCharacter(_ character: Character) -> Bool {
        guard let value = character.asciiValue else { return false }
        switch value {
        case UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "a")...UInt8(ascii: "z"),
            UInt8(ascii: "A")...UInt8(ascii: "Z"):
            return true
        default:
            return "!#$%&'*+-.^_`|~".utf8.contains(value)
        }
    }
}

/// What the listener does with a parsed request.
enum LoopbackRoute: Equatable {
    /// The redirect: deliver this origin-form target to the caller.
    case callback(target: String)
    case reject(status: Int)

    /// Decides the route. A `Host` other than the loopback address on this port is refused first, so a
    /// page served from another origin through DNS rebinding cannot reach the redirect (RFC 8252 §8.3).
    static func route(_ head: LoopbackRequestHead, path: String, port: UInt16) -> LoopbackRoute {
        guard let host = head.headers["host"]?.lowercased(), host == "127.0.0.1:\(port)" || host == "localhost:\(port)"
        else { return .reject(status: 400) }
        guard head.method == "GET" else { return .reject(status: 405) }
        guard head.path == path else { return .reject(status: 404) }
        return .callback(target: head.target)
    }
}
