import Foundation

/// A credential value such as a token, authorization code, PKCE verifier or client secret.
///
/// ``description``, ``debugDescription`` and reflection (`dump`, `Mirror`) never show the
/// value; call ``reveal()`` at the single place the value must be sent or stored. A `Secret`
/// is encoded and decoded as a plain string so credential stores can persist it.
///
/// - Important: `Codable` encodes the value in **plaintext**, by design: persistence needs the real
///   value. Never encode a `Secret` into logs, analytics, crash reports or unprotected files; write it only to
///   secure storage such as the Keychain.
/// - `==` is not constant time. Compare secrets you hold against attacker-supplied input with
///   ``reveal()`` and a constant-time routine; the library does so for `state`.
public struct Secret: Sendable, Hashable, Codable, CustomStringConvertible, CustomDebugStringConvertible,
    CustomReflectable
{
    private let value: String

    /// Wraps `value` as a secret.
    public init(_ value: String) {
        self.value = value
    }

    /// Returns the wrapped value. Never log or interpolate the result.
    public func reveal() -> String {
        value
    }

    /// Always `<redacted>`.
    public var description: String { "<redacted>" }

    /// Always `<redacted>`.
    public var debugDescription: String { "<redacted>" }

    /// A mirror without children, so `dump` and debugger views show nothing.
    public var customMirror: Mirror { Mirror(self, children: [], displayStyle: .struct) }

    /// Decodes a secret from a plain string.
    public init(from decoder: any Decoder) throws {
        value = try decoder.singleValueContainer().decode(String.self)
    }

    /// Encodes the secret as a plain string.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }
}
