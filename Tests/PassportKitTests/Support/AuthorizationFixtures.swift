import Foundation

@testable import PassportKit

/// Test-only random source: the n-th call returns 32 bytes of value n, so state and verifier are predictable.
final class CountingRandomSource: RandomSource, @unchecked Sendable {
    // @unchecked Sendable: `calls` is only touched under `lock`.
    private let lock = NSLock()
    private var calls = 0

    func bytes(count: Int) -> [UInt8] {
        let call = lock.withLock {
            calls += 1
            return calls
        }
        return [UInt8](repeating: UInt8(call), count: count)
    }

    /// The base64url text of 32 bytes of `call`.
    static func text(call: Int) -> String { Base64URL.encode([UInt8](repeating: UInt8(call), count: 32)) }
}

/// Test-only user agent that records what it was shown and answers with a scripted callback or error.
actor FakeUserAgent: UserAgent {
    enum Behavior: Sendable {
        case callback(@Sendable (URL) -> URL)
        case fail(any Error)
    }

    private let behavior: Behavior
    private(set) var presented: [(url: URL, redirectURI: URL)] = []

    init(_ behavior: Behavior) { self.behavior = behavior }

    func present(_ url: URL, redirectURI: URL) async throws -> URL {
        presented.append((url, redirectURI))
        switch behavior {
        case .callback(let make): return make(url)
        case .fail(let error): throw error
        }
    }
}

enum AuthorizationFixtures {
    static let redirectURI = URL(string: "https://app.example.com/callback")!
    static let issuer = URL(string: "https://as.example.com")!

    /// The decoded query items of an authorization URL.
    static func query(of url: URL) -> [(String, String)] {
        FormEncoding.decode(
            Data((URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedQuery ?? "").utf8))
            ?? []
    }

    /// A callback to `redirectURI` carrying `parameters`.
    static func callback(_ parameters: [(String, String)], to redirectURI: URL = redirectURI) -> URL {
        var components = URLComponents(url: redirectURI, resolvingAgainstBaseURL: false)!
        components.percentEncodedQuery = String(decoding: FormEncoding.encode(parameters), as: UTF8.self)
        return components.url!
    }

    /// The `state` the authorization URL carries.
    static func state(of url: URL) -> String { query(of: url).first { $0.0 == "state" }?.1 ?? "" }
}
