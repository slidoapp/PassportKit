import Foundation
import Testing

@testable import PassportKit

struct PKCETests {
    struct FixedRandom: RandomSource {
        var byte: UInt8
        var count: Int?
        func bytes(count requested: Int) -> [UInt8] {
            [UInt8](repeating: byte, count: count ?? requested)
        }
    }

    @Test func rfc7636AppendixBChallenge() {
        let verifier = Secret("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        #expect(PKCE.challenge(for: verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    @Test func rfc7636AppendixBOctetsEncodeToTheVerifier() {
        let octets: [UInt8] = [
            116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187, 186, 22, 212, 37, 77, 105, 214, 191,
            240, 91, 88, 5, 88, 83, 132, 141, 121,
        ]
        #expect(Base64URL.encode(octets) == "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
    }

    @Test func verifierIs43CharactersOfBase64URL() throws {
        let verifier = try PKCE.makeVerifier(random: SystemRandomSource()).reveal()
        #expect(verifier.count == 43)
        #expect(verifier.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_") })
    }

    @Test func verifiersDiffer() throws {
        let first = try PKCE.makeVerifier(random: SystemRandomSource())
        let second = try PKCE.makeVerifier(random: SystemRandomSource())
        #expect(first != second)
    }

    @Test func verifierIsDeterministicForAFixedRandomSource() throws {
        let verifier = try PKCE.makeVerifier(random: FixedRandom(byte: 0xFF))
        #expect(verifier.reveal() == String(repeating: "_", count: 42) + "8")
    }

    @Test func shortRandomSourceIsRejected() {
        #expect {
            try PKCE.makeVerifier(random: FixedRandom(byte: 1, count: 31))
        } throws: { error in
            (error as? PassportError)?.code == .invalidConfiguration
        }
    }

    @Test(
        arguments: [
            ([], ""),
            ([0xFF], "_w"),
            ([0xFB, 0xFF], "-_8"),
            ([0xFB, 0xFF, 0xBF], "-_-_"),
            ([0x66, 0x6F, 0x6F], "Zm9v"),
            ([0x66, 0x6F], "Zm8"),
        ] as [([UInt8], String)])
    func base64URL(bytes: [UInt8], expected: String) {
        #expect(Base64URL.encode(bytes) == expected)
    }
}
