import Foundation

/// HTTP header fields: case-insensitive names, several values per name, insertion order preserved.
///
/// Header values can carry credentials (`Authorization`, `Cookie`), so descriptions and reflection show the
/// header names only.
public struct HTTPHeaders: Sendable, Hashable, Sequence, ExpressibleByDictionaryLiteral, CustomStringConvertible,
    CustomDebugStringConvertible, CustomReflectable
{
    /// One header line.
    public typealias Element = (name: String, value: String)

    private struct Entry: Sendable {
        var name: String
        var value: String
        var key: String { name.lowercased() }
    }

    private var entries: [Entry]

    /// Creates empty headers.
    public init() {
        entries = []
    }

    /// Creates headers from a dictionary literal; repeated names are kept as separate lines.
    public init(dictionaryLiteral elements: (String, String)...) {
        entries = elements.map { Entry(name: $0.0, value: $0.1) }
    }

    /// The first value for `name`, or `nil`. Setting replaces every line with that name; `nil` removes them.
    public subscript(name: String) -> String? {
        get {
            let key = name.lowercased()
            return entries.first { $0.key == key }?.value
        }
        set {
            let key = name.lowercased()
            let position = entries.firstIndex { $0.key == key }
            entries.removeAll { $0.key == key }
            guard let newValue else { return }
            entries.insert(Entry(name: name, value: newValue), at: Swift.min(position ?? entries.count, entries.count))
        }
    }

    /// All values for `name` in order, for example several `WWW-Authenticate` lines.
    public func values(for name: String) -> [String] {
        let key = name.lowercased()
        return entries.filter { $0.key == key }.map(\.value)
    }

    /// Appends a line, keeping existing lines with the same name.
    public mutating func add(name: String, value: String) {
        entries.append(Entry(name: name, value: value))
    }

    /// The distinct header names as first written, in order. Safe to log: values are not included.
    public var names: [String] {
        var seen = Set<String>()
        return entries.filter { seen.insert($0.key).inserted }.map(\.name)
    }

    /// Iterates all lines in order.
    public func makeIterator() -> IndexingIterator<[Element]> {
        entries.map { (name: $0.name, value: $0.value) }.makeIterator()
    }

    /// Equal when the same lines appear in the same order, ignoring name case.
    public static func == (lhs: HTTPHeaders, rhs: HTTPHeaders) -> Bool {
        lhs.entries.map { [$0.key, $0.value] } == rhs.entries.map { [$0.key, $0.value] }
    }

    /// Hashes consistently with `==`.
    public func hash(into hasher: inout Hasher) {
        for entry in entries {
            hasher.combine(entry.key)
            hasher.combine(entry.value)
        }
    }

    /// The header names without values.
    public var description: String { "HTTPHeaders(\(names))" }

    /// The header names without values.
    public var debugDescription: String { description }

    /// A mirror exposing the names only, so `dump` never shows values.
    public var customMirror: Mirror { Mirror(self, children: ["names": names], displayStyle: .struct) }
}
