import Foundation
import Testing

@testable import PassportKit

@Suite("Resource indicators (RFC 8707 §2)")
struct ResourceIndicatorTests {
    private func encoded(_ resources: [String]) throws -> [String] {
        var list = ParameterList()
        try list.add(resources: resources.map { try #require(URL(string: $0)) })
        return list.items.map { "\($0.0)=\($0.1)" }
    }

    @Test(arguments: [
        "https://api.example.com/v1", "urn:example:api",
        // RFC 8707 §2 says a query SHOULD NOT be used; it is allowed because some resources are identified by one.
        "https://api.example.com/v1?tenant=a",
    ])
    func acceptsAnAbsoluteURI(resource: String) throws {
        #expect(try encoded([resource]) == ["resource=\(resource)"])
    }

    @Test(arguments: ["https://api.example.com/v1#part", "/relative/path", "api.example.com"])
    func rejectsAFragmentOrARelativeReference(resource: String) {
        #expect(throws: PassportError(.invalidConfiguration)) { try encoded([resource]) }
    }
}
