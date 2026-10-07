import Foundation
import Testing

@testable import PassportKit

struct JSONValueTests {
    @Test func roundTripsEveryCase() throws {
        let value = JSONValue.object([
            "string": .string("é😀"),
            "number": .number(1.5),
            "integer": .number(42),
            "bool": .bool(false),
            "array": .array([.null, .string("x"), .array([])]),
            "object": .object(["nested": .bool(true)]),
            "null": .null,
        ])
        let data = try JSONEncoder().encode(value)
        #expect(try JSONDecoder().decode(JSONValue.self, from: data) == value)
    }

    @Test func decodesArbitraryJSON() throws {
        let json = #"{"a":[1,"two",true,null,{"b":2.5}]}"#
        let value = try JSONDecoder().decode(JSONValue.self, from: Data(json.utf8))
        #expect(
            value
                == .object([
                    "a": .array([.number(1), .string("two"), .bool(true), .null, .object(["b": .number(2.5)])])
                ]))
    }

    @Test func booleansAreNotNumbers() throws {
        #expect(try JSONDecoder().decode(JSONValue.self, from: Data("true".utf8)) == .bool(true))
        #expect(try JSONDecoder().decode(JSONValue.self, from: Data("1".utf8)) == .number(1))
    }
}
