import Foundation
import Testing

@testable import PassportKit

#if canImport(CryptoKit)
    import CryptoKit
#endif

struct SHA256Tests {
    static let vectors: [(message: String, digest: String)] = [
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        (
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        ),
        (
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        ),
    ]

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    @Test(arguments: vectors)
    func pureSwiftMatchesNISTVectors(message: String, digest: String) {
        #expect(hex(PureSwiftSHA256.hash(Array(message.utf8))) == digest)
    }

    @Test(arguments: vectors)
    func platformHasherMatchesNISTVectors(message: String, digest: String) {
        #expect(hex(SHA256Hasher.hash(Array(message.utf8))) == digest)
    }

    @Test func pureSwiftHandlesMillionAs() {
        let message = [UInt8](repeating: UInt8(ascii: "a"), count: 1_000_000)
        #expect(
            hex(PureSwiftSHA256.hash(message)) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
    }

    #if canImport(CryptoKit)
        @Test(arguments: [0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1_000])
        func pureSwiftMatchesCryptoKitAtBlockBoundaries(length: Int) {
            let message = (0..<length).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) }
            #expect(PureSwiftSHA256.hash(message) == Array(CryptoKit.SHA256.hash(data: message)))
        }
    #endif
}
