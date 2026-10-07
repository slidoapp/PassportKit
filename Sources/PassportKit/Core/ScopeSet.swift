import Foundation

/// A set of scope tokens: space-delimited, case-sensitive and order-insensitive (RFC 6749 §3.3).
///
/// Encoded and decoded as the space-delimited string ``rawValue``.
public struct ScopeSet: Sendable, Hashable, Codable, ExpressibleByArrayLiteral, CustomStringConvertible {
    /// The individual scope tokens.
    public private(set) var scopes: Set<String>

    /// Creates a set from tokens. Elements containing spaces are split and empty tokens are dropped.
    public init(_ scopes: some Sequence<String>) {
        self.scopes = Set(scopes.flatMap { $0.split(separator: " ").map(String.init) })
    }

    /// Parses a space-delimited scope string, dropping empty items (RFC 6749 §3.3).
    public init(parsing value: String) {
        self.init([value])
    }

    /// Creates a set from an array literal.
    public init(arrayLiteral elements: String...) {
        self.init(elements)
    }

    /// The tokens sorted and joined by single spaces; deterministic for equal sets.
    public var rawValue: String {
        scopes.sorted().joined(separator: " ")
    }

    /// Whether the set has no tokens.
    public var isEmpty: Bool { scopes.isEmpty }

    /// Whether the set contains `scope` (case-sensitive).
    public func contains(_ scope: String) -> Bool {
        scopes.contains(scope)
    }

    /// Whether every token of this set is also in `other`.
    public func isSubset(of other: ScopeSet) -> Bool {
        scopes.isSubset(of: other.scopes)
    }

    /// The tokens as ``rawValue``.
    public var description: String { rawValue }

    /// Decodes a space-delimited string.
    public init(from decoder: any Decoder) throws {
        self.init(parsing: try decoder.singleValueContainer().decode(String.self))
    }

    /// Encodes ``rawValue`` as a string.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}
