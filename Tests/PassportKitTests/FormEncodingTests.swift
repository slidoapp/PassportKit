import Foundation
import Testing

@testable import PassportKit

struct FormEncodingTests {
    @Test(arguments: [
        ("a+b c", "a%2Bb+c"),
        ("a&b", "a%26b"),
        ("a=b", "a%3Db"),
        ("~-._", "~-._"),
        ("AZaz09", "AZaz09"),
        ("é", "%C3%A9"),
        ("😀", "%F0%9F%98%80"),
        ("", ""),
        (" ", "+"),
        ("/:?#[]@!$'()*,;%", "%2F%3A%3F%23%5B%5D%40%21%24%27%28%29%2A%2C%3B%25"),
        ("line\nbreak", "line%0Abreak"),
    ])
    func componentVectors(input: String, expected: String) {
        #expect(FormEncoding.encodeComponent(input) == expected)
    }

    @Test func encodesPairsInOrderWithRepeats() {
        let data = FormEncoding.encode([
            ("scope", "a b"), ("resource", "https://x"), ("resource", "https://y"), ("e", ""),
        ])
        #expect(String(data: data, encoding: .utf8) == "scope=a+b&resource=https%3A%2F%2Fx&resource=https%3A%2F%2Fy&e=")
    }

    @Test func encodesEmptyListAsEmptyBody() {
        #expect(FormEncoding.encode([]).isEmpty)
    }

    @Test func decodeRoundTrips() throws {
        let pairs = [("a b", "c+d&e=f"), ("é", "😀"), ("empty", ""), ("a b", "again")]
        let decoded = try #require(FormEncoding.decode(FormEncoding.encode(pairs)))
        #expect(decoded.map(\.0) == pairs.map(\.0))
        #expect(decoded.map(\.1) == pairs.map(\.1))
    }

    @Test func decodeRejectsMalformedInput() {
        #expect(FormEncoding.decode(Data("a=%zz".utf8)) == nil)
        #expect(FormEncoding.decode(Data("a=%4".utf8)) == nil)
        #expect(FormEncoding.decode(Data("a=%FF".utf8)) == nil)
    }

    @Test func decodeHandlesMissingValueAndEmptySegments() throws {
        let decoded = try #require(FormEncoding.decode(Data("a&&b=1=2".utf8)))
        #expect(decoded.map(\.0) == ["a", "b"])
        #expect(decoded.map(\.1) == ["", "1=2"])
    }
}
