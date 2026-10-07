import Foundation

/// One challenge of a `WWW-Authenticate` header (RFC 9110 §11.6.1, RFC 6750 §3).
///
/// Parsing is lenient and never fails: input that is not a challenge yields no challenge, and a malformed
/// part is skipped.
public struct AuthenticationChallenge: Sendable, Hashable {
    /// The authentication scheme, lower-cased because schemes are case-insensitive (RFC 9110 §11.1).
    public var scheme: String
    /// The `auth-param`s with lower-cased names (RFC 9110 §11.2). Values are unquoted and unescaped. When a
    /// name repeats, the first value is kept.
    public var parameters: [String: String]
    /// The `token68` form of the credentials, for example `abc==` in `Negotiate abc==`; `nil` otherwise.
    public var token68: String?

    /// Creates a challenge.
    public init(scheme: String, parameters: [String: String] = [:], token68: String? = nil) {
        self.scheme = scheme
        self.parameters = parameters
        self.token68 = token68
    }

    /// Parses the values of every `WWW-Authenticate` (or `Proxy-Authenticate`) header line, in order.
    ///
    /// Each value is a comma-separated list of challenges (RFC 9110 §11.6.1) and several lines are allowed;
    /// commas and escaped quotes inside a quoted string do not split. See ``HTTPHeaders/values(for:)``.
    public static func parse(_ headerValues: [String]) -> [AuthenticationChallenge] {
        headerValues.flatMap { value in
            var scanner = Scanner(bytes: Array(value.utf8))
            return scanner.challenges()
        }
    }
}

extension AuthenticationChallenge {
    /// A hand-written scanner over the UTF-8 bytes of one header value. Every loop iteration consumes at least
    /// one byte, so malformed input terminates.
    fileprivate struct Scanner {
        let bytes: [UInt8]
        var index = 0

        init(bytes: [UInt8]) { self.bytes = bytes }

        private var atEnd: Bool { index >= bytes.count }

        mutating func challenges() -> [AuthenticationChallenge] {
            var result: [AuthenticationChallenge] = []
            while true {
                skipSeparators()
                guard !atEnd else { return result }
                guard let scheme = scanToken() else {
                    skipGarbage()
                    continue
                }
                var challenge = AuthenticationChallenge(scheme: scheme.lowercased())
                scanCredentials(into: &challenge)
                result.append(challenge)
            }
        }

        /// Reads the `token68` or the `auth-param` list after the scheme, up to the next challenge.
        private mutating func scanCredentials(into challenge: inout AuthenticationChallenge) {
            guard !atEnd, isSpace(bytes[index]) else { return }
            skipSpaces()
            var isFirst = true
            while true {
                let separatorsStart = index
                skipSeparators()
                // A comma before the first item ends this challenge's credentials: the item is a new scheme.
                if bytes[separatorsStart..<index].contains(comma) { isFirst = false }
                guard !atEnd else { return }
                let itemStart = index
                guard let name = scanName() else {
                    skipGarbage()
                    continue
                }
                let nameEnd = index
                skipSpaces()
                if !atEnd, bytes[index] == equals {
                    let equalsStart = index
                    var equalsCount = 0
                    while !atEnd, bytes[index] == equals {
                        equalsCount += 1
                        index += 1
                    }
                    let valueStart = index
                    skipSpaces()
                    if atEnd || bytes[index] == comma {
                        // `abc=` or `abc==`: padding of a token68, never an empty parameter value.
                        if isFirst, equalsStart == nameEnd {
                            challenge.token68 = name + String(repeating: "=", count: equalsCount)
                            return
                        }
                        continue
                    }
                    guard equalsCount == 1 else {
                        skipGarbage()
                        continue
                    }
                    index = valueStart
                    skipSpaces()
                    let value = bytes[index] == quote ? scanQuoted() : scanUnquoted()
                    let key = name.lowercased()
                    if challenge.parameters[key] == nil { challenge.parameters[key] = value }
                    isFirst = false
                } else if isFirst, atEnd || bytes[index] == comma {
                    challenge.token68 = name
                    return
                } else {
                    // A bare token among parameters starts the next challenge.
                    index = itemStart
                    return
                }
            }
        }

        // MARK: Lexical pieces

        private let comma = UInt8(ascii: ",")
        private let equals = UInt8(ascii: "=")
        private let quote = UInt8(ascii: "\"")
        private let backslash = UInt8(ascii: "\\")

        private func isSpace(_ byte: UInt8) -> Bool { byte == 0x20 || byte == 0x09 }

        /// `tchar` (RFC 9110 §5.6.2).
        private func isTokenCharacter(_ byte: UInt8) -> Bool {
            switch byte {
            case UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"),
                UInt8(ascii: "0")...UInt8(ascii: "9"):
                true
            default:
                "!#$%&'*+-.^_`|~".utf8.contains(byte)
            }
        }

        private mutating func skipSpaces() {
            while !atEnd, isSpace(bytes[index]) { index += 1 }
        }

        private mutating func skipSeparators() {
            while !atEnd, isSpace(bytes[index]) || bytes[index] == comma { index += 1 }
        }

        /// Skips to the next comma outside a quoted string, consuming at least one byte.
        private mutating func skipGarbage() {
            repeat {
                if bytes[index] == quote {
                    _ = scanQuoted()
                } else {
                    index += 1
                }
            } while !atEnd && bytes[index] != comma
        }

        private mutating func scanToken() -> String? {
            let start = index
            while !atEnd, isTokenCharacter(bytes[index]) { index += 1 }
            return index > start ? String(decoding: bytes[start..<index], as: UTF8.self) : nil
        }

        /// A parameter name or `token68` body: token characters plus `/`.
        private mutating func scanName() -> String? {
            let start = index
            while !atEnd, isTokenCharacter(bytes[index]) || bytes[index] == UInt8(ascii: "/") { index += 1 }
            return index > start ? String(decoding: bytes[start..<index], as: UTF8.self) : nil
        }

        /// Leniently reads up to a space, comma or quote.
        private mutating func scanUnquoted() -> String {
            let start = index
            while !atEnd, !isSpace(bytes[index]), bytes[index] != comma, bytes[index] != quote { index += 1 }
            return String(decoding: bytes[start..<index], as: UTF8.self)
        }

        /// A `quoted-string` with `quoted-pair` escapes; an unterminated string runs to the end of the input.
        private mutating func scanQuoted() -> String {
            index += 1
            var value: [UInt8] = []
            while !atEnd {
                let byte = bytes[index]
                index += 1
                if byte == quote { break }
                if byte == backslash, !atEnd {
                    value.append(bytes[index])
                    index += 1
                } else {
                    value.append(byte)
                }
            }
            return String(decoding: value, as: UTF8.self)
        }
    }
}
