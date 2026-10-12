import HTTPTypes

extension HTTPFields {
    /// Replaces every line named `name` with one that HPACK and QPACK never index, nor let intermediaries index
    /// (RFC 7541 §7.1.3). For credentials such as `Authorization`.
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
