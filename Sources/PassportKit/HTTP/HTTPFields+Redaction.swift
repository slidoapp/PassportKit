import HTTPTypes

extension HTTPFields {
    /// Replaces every line named `name` with one marked never indexed (RFC 7541 §7.1.3), for credentials such as
    /// `Authorization`.
    ///
    /// The marking reaches the wire only through an ``HTTPTransport`` that keeps the `indexingStrategy` of
    /// `HTTPFields` when it encodes HPACK or QPACK. ``URLSessionTransport`` does not: `URLRequest` has no
    /// indexing strategy, so `URLSession` decides how to encode the field.
    package mutating func setSensitive(_ name: HTTPField.Name, _ value: String) {
        self[name] = nil
        var field = HTTPField(name: name, value: value)
        field.indexingStrategy = .disallow
        append(field)
    }

    /// The distinct field names as first written, in order. Safe to describe: values are not included.
    package var names: [String] {
        var seen = Set<HTTPField.Name>()
        return compactMap { seen.insert($0.name).inserted ? $0.name.rawName : nil }
    }
}
