import Foundation
import Testing

@testable import PassportKit

struct SecretTests {
    @Test func redactsEveryRendering() {
        let secret = Secret(Canary.value)
        for text in Canary.renderings(of: secret) {
            #expect(!text.contains(Canary.value))
        }
        #expect(secret.description == "<redacted>")
        #expect(secret.debugDescription == "<redacted>")
    }

    @Test func redactsWhenNestedInCollections() {
        let nested = [Secret(Canary.value): [Secret(Canary.value)]]
        for text in Canary.renderings(of: nested) {
            #expect(!text.contains(Canary.value))
        }
    }

    @Test func revealReturnsValue() {
        #expect(Secret("abc").reveal() == "abc")
    }

    @Test func codableUsesPlainString() throws {
        let encoded = try JSONEncoder().encode([Secret("abc")])
        #expect(String(data: encoded, encoding: .utf8) == #"["abc"]"#)
        let decoded = try JSONDecoder().decode([Secret].self, from: encoded)
        #expect(decoded == [Secret("abc")])
    }
}
