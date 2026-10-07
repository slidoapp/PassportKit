import Foundation
import Testing

@testable import PassportKit

struct PassportErrorTests {
    @Test func equalityComparesCodeRecoveryAndStatusOnly() {
        let lhs = PassportError(.invalidGrant, recovery: .reauthenticate, statusCode: 400, detail: "one")
        let rhs = PassportError(.invalidGrant, recovery: .reauthenticate, statusCode: 400, detail: "two")
        #expect(lhs == rhs)
        #expect(lhs != PassportError(.invalidGrant, recovery: .reauthenticate, statusCode: 401))
        #expect(lhs != PassportError(.invalidGrant, recovery: .noAction, statusCode: 400))
        #expect(lhs != PassportError(.invalidClient, recovery: .reauthenticate, statusCode: 400))
    }

    @Test func localizedDescriptionIsTheRedactedDescription() {
        struct Leaky: Error, CustomStringConvertible {
            var description: String { Canary.value }
        }
        let error = PassportError(.invalidGrant, statusCode: 400, detail: "expired", underlying: Leaky())
        #expect(error.localizedDescription == error.description)
        #expect(error.localizedDescription.contains("invalid_grant"))
        #expect(!error.localizedDescription.contains(Canary.value))
    }

    @Test func codeRoundTripsAsAPlainString() throws {
        let data = try JSONEncoder().encode([PassportError.Code.invalidGrant, PassportError.Code(rawValue: "custom")])
        #expect(String(decoding: data, as: UTF8.self) == #"["invalid_grant","custom"]"#)
        #expect(try JSONDecoder().decode([PassportError.Code].self, from: data).last?.rawValue == "custom")
    }

    @Test func descriptionsNeverShowSecretsOrUnderlyingDetails() {
        struct Leaky: Error, CustomStringConvertible {
            var description: String { Canary.value }
        }
        let error = PassportError(.transportFailure, detail: "failed", underlying: Leaky())
        for text in Canary.renderings(of: error) {
            #expect(!text.contains(Canary.value))
        }
    }

    @Test func detailRedactsTokenLikeRunsAndControlCharacters() {
        let error = PassportError(
            .invalidGrant,
            detail: "Bad token \(Canary.value)-abcdefghij\nsecond\tline"
        )
        let text = error.detail ?? ""
        #expect(!text.contains(Canary.value))
        #expect(text == "Bad token <redacted> second line")
        for rendering in Canary.renderings(of: error) {
            #expect(!rendering.contains(Canary.value))
        }
    }

    @Test func detailDropsInvisibleFormatCharacters() {
        // U+202E right-to-left override, U+200B zero-width space, U+2028 line separator.
        let error = PassportError(.invalidGrant, detail: "ok\u{202E}gnp.exe\u{200B}x\u{2028}end")
        #expect(error.detail == "okgnp.exex end")
    }

    @Test func detailIsTruncated() {
        let text = String(repeating: "word ", count: 200)
        let error = PassportError(.serverError, detail: text)
        #expect(error.detail?.count == 200)
        #expect(
            PassportError(.serverError, detail: String(repeating: "x", count: 500)).detail?.count
                == 10)
    }
}
