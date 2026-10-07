/// Proof Key for Code Exchange, S256 only (RFC 7636).
enum PKCE {
    /// Entropy of a verifier in bytes; RFC 7636 §4.1 recommends 32 octets, giving 43 characters.
    static let verifierByteCount = 32

    /// A new `code_verifier`: 32 random bytes as base64url without padding (RFC 7636 §4.1).
    static func makeVerifier(random: any RandomSource) throws -> Secret {
        try makeRandomValue(random: random)
    }

    /// 32 random bytes as base64url without padding: a verifier, or an unguessable `state` (RFC 6749 §10.12).
    static func makeRandomValue(random: any RandomSource) throws -> Secret {
        let bytes = random.bytes(count: verifierByteCount)
        guard bytes.count == verifierByteCount else {
            throw PassportError(.invalidConfiguration, detail: "The random source returned too few bytes.")
        }
        return Secret(Base64URL.encode(bytes))
    }

    /// The S256 `code_challenge`: base64url of the SHA-256 of the ASCII verifier (RFC 7636 §4.2).
    static func challenge(for verifier: Secret) -> String {
        Base64URL.encode(SHA256Hasher.hash(Array(verifier.reveal().utf8)))
    }

    /// The only supported `code_challenge_method` (RFC 7636 §4.3).
    static let challengeMethod = "S256"
}
