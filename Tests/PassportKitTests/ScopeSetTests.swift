import Foundation
import Testing

@testable import PassportKit

struct ScopeSetTests {
    @Test(
        arguments: [
            ("read write", ["read", "write"]),
            ("  read   write ", ["read", "write"]),
            ("", []),
            ("   ", []),
            ("Read read", ["Read", "read"]),
            ("a a", ["a"]),
        ] as [(String, [String])])
    func parsing(text: String, expected: [String]) {
        #expect(ScopeSet(parsing: text).scopes == Set(expected))
    }

    @Test func equalityIgnoresOrder() {
        #expect(ScopeSet(parsing: "b a") == ["a", "b"])
        #expect(ScopeSet(parsing: "a b").hashValue == ScopeSet(parsing: "b a").hashValue)
    }

    @Test func rawValueIsSortedAndDeterministic() {
        #expect(ScopeSet(["write", "read", "openid"]).rawValue == "openid read write")
        #expect(ScopeSet([]).rawValue == "")
    }

    @Test func scopesAreCaseSensitive() {
        #expect(ScopeSet(["Read"]) != ScopeSet(["read"]))
        #expect(!ScopeSet(["Read"]).contains("read"))
    }

    @Test func subset() {
        #expect(ScopeSet(["a"]).isSubset(of: ["a", "b"]))
        #expect(!ScopeSet(["a", "c"]).isSubset(of: ["a", "b"]))
        #expect(ScopeSet([]).isSubset(of: []))
    }

    @Test func codableUsesSpaceDelimitedString() throws {
        let encoded = try JSONEncoder().encode([ScopeSet(["b", "a"])])
        #expect(String(data: encoded, encoding: .utf8) == #"["a b"]"#)
        #expect(try JSONDecoder().decode([ScopeSet].self, from: encoded) == [["a", "b"]])
    }
}
