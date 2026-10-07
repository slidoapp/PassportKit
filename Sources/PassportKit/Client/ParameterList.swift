import Foundation

/// Ordered standard request parameters in wire order, shared by form bodies and the authorization URL query.
struct ParameterList {
    private(set) var items: [(String, String)] = []

    mutating func add(_ name: String, _ value: String) {
        items.append((name, value))
    }

    mutating func add(scope: ScopeSet?) {
        if let scope, !scope.isEmpty { add("scope", scope.rawValue) }
    }

    /// Adds repeated `resource` parameters (RFC 8707 §2): absolute URLs without a fragment.
    mutating func add(resources: [URL]) throws {
        for resource in resources {
            let text = resource.absoluteString
            guard resource.scheme != nil, resource.host?.isEmpty == false, !text.contains("#") else {
                throw PassportError(
                    .invalidConfiguration,
                    detail: "A resource indicator must be an absolute URL without a fragment."
                )
            }
            add("resource", text)
        }
    }
}
