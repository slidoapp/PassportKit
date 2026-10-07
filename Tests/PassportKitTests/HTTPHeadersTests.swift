import Foundation
import Testing

@testable import PassportKit

struct HTTPHeadersTests {
    @Test func namesAreCaseInsensitive() {
        let headers: HTTPHeaders = ["Content-Type": "text/plain"]
        #expect(headers["content-type"] == "text/plain")
        #expect(headers["CONTENT-TYPE"] == "text/plain")
        #expect(headers["Accept"] == nil)
    }

    @Test func keepsMultipleValuesInOrder() {
        var headers = HTTPHeaders()
        headers.append("WWW-Authenticate", "Bearer realm=\"a\"")
        headers.append("www-authenticate", "Basic")
        #expect(headers.values(for: "WWW-AUTHENTICATE") == ["Bearer realm=\"a\"", "Basic"])
        #expect(headers["www-authenticate"] == "Bearer realm=\"a\"")
        #expect(headers.names == ["WWW-Authenticate"])
    }

    @Test func settingReplacesAllLinesAndKeepsPosition() {
        var headers: HTTPHeaders = ["A": "1", "B": "2", "a": "3"]
        headers["a"] = "9"
        #expect(headers.map(\.name) == ["a", "B"])
        #expect(headers.map(\.value) == ["9", "2"])
    }

    @Test func settingNilRemoves() {
        var headers: HTTPHeaders = ["A": "1", "B": "2", "a": "3"]
        headers["A"] = nil
        #expect(headers.map(\.name) == ["B"])
    }

    @Test func iteratesInInsertionOrder() {
        var headers = HTTPHeaders()
        headers["Z"] = "1"
        headers["A"] = "2"
        #expect(headers.map(\.name) == ["Z", "A"])
    }

    @Test func equalityIgnoresNameCase() {
        let lhs: HTTPHeaders = ["Content-Type": "x"]
        let rhs: HTTPHeaders = ["content-type": "x"]
        #expect(lhs == rhs)
        #expect(lhs.hashValue == rhs.hashValue)
        #expect(lhs != ["content-type": "y"])
    }
}
