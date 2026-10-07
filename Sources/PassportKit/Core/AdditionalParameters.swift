import Foundation

/// Ordered request parameters that may repeat, used for extensions on every request.
///
/// Additional parameters are appended after the standard parameters a request builder sets.
/// A name equal to a standard parameter, or to a client authentication parameter (`client_id`,
/// `client_secret`), is a configuration error: RFC 6749 §2.3 allows one authentication method per request. Descriptions list names
/// only, because values may be credentials.
public struct AdditionalParameters: Sendable, Hashable, ExpressibleByDictionaryLiteral, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    /// One name and value pair.
    public struct Item: Sendable, Hashable {
        /// The parameter name.
        public var name: String
        /// The parameter value.
        public var value: String
    }

    /// The parameters in insertion order; names may repeat.
    public private(set) var items: [Item]

    /// Creates an empty list.
    public init() {
        items = []
    }

    /// Creates a list from a dictionary literal, keeping order and repeated names.
    public init(dictionaryLiteral elements: (String, String)...) {
        items = elements.map { Item(name: $0.0, value: $0.1) }
    }

    /// Whether there are no parameters.
    public var isEmpty: Bool { items.isEmpty }

    /// Appends a parameter after the existing ones.
    public mutating func append(_ name: String, _ value: String) {
        items.append(Item(name: name, value: value))
    }

    /// Returns `standard` followed by these parameters.
    ///
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/invalidConfiguration``
    /// when a name equals one in `standard` or `reserving` (names are case-sensitive).
    func appending(to standard: [(String, String)], reserving extra: Set<String> = []) throws -> [(String, String)] {
        let reserved = Set(standard.map { $0.0 }).union(extra)
        if let collision = items.first(where: { reserved.contains($0.name) }) {
            throw PassportError(
                .invalidConfiguration,
                detail: "Additional parameter '\(collision.name)' collides with a standard parameter."
            )
        }
        return standard + items.map { ($0.name, $0.value) }
    }

    /// The parameter names.
    public var description: String { "AdditionalParameters(names: \(items.map(\.name)))" }

    /// The parameter names.
    public var debugDescription: String { description }

    /// A mirror exposing names only.
    public var customMirror: Mirror { Mirror(self, children: ["names": items.map(\.name)], displayStyle: .struct) }
}
