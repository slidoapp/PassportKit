import Foundation
import Testing

@testable import PassportKit

struct PassportErrorTests {
    @Test func equalityComparesCodeRecoveryAndStatusOnly() {
        let lhs = PassportError(.invalidGrant, recovery: .reauthenticate, statusCode: 400, errorDescription: "one")
        let rhs = PassportError(.invalidGrant, recovery: .reauthenticate, statusCode: 400, errorDescription: "two")
        #expect(lhs == rhs)
        #expect(lhs != PassportError(.invalidGrant, recovery: .reauthenticate, statusCode: 401))
        #expect(lhs != PassportError(.invalidGrant, recovery: .none, statusCode: 400))
        #expect(lhs != PassportError(.invalidClient, recovery: .reauthenticate, statusCode: 400))
    }

    @Test func descriptionsNeverShowSecretsOrUnderlyingDetails() {
        struct Leaky: Error, CustomStringConvertible {
            var description: String { Canary.value }
        }
        let error = PassportError(.transportFailure, errorDescription: "failed", underlying: Leaky())
        for text in Canary.renderings(of: error) {
            #expect(!text.contains(Canary.value))
        }
    }

    @Test func errorDescriptionRedactsTokenLikeRunsAndControlCharacters() {
        let error = PassportError(
            .invalidGrant,
            errorDescription: "Bad token \(Canary.value)-abcdefghij\nsecond\tline"
        )
        let text = error.errorDescription ?? ""
        #expect(!text.contains(Canary.value))
        #expect(text == "Bad token <redacted> second line")
        for rendering in Canary.renderings(of: error) {
            #expect(!rendering.contains(Canary.value))
        }
    }

    @Test func errorDescriptionIsTruncated() {
        let text = String(repeating: "word ", count: 200)
        let error = PassportError(.serverError, errorDescription: text)
        #expect(error.errorDescription?.count == 200)
        #expect(
            PassportError(.serverError, errorDescription: String(repeating: "x", count: 500)).errorDescription?.count
                == 10)
    }
}
