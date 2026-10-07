import Foundation

/// The versioned JSON encoding for stored credentials, for `CredentialStore` implementations that write bytes.
///
/// A record is the credential's members next to `"version": 1`. Token values appear as plain strings: the
/// encoded bytes are secrets and belong in protected storage only.
public enum CredentialCoding {
    /// The record version written by ``encode(_:)``.
    static let currentVersion = 1

    private struct Header: Decodable {
        var version: Int
    }

    /// Encodes `credential` as a version 1 record.
    public static func encode(_ credential: Credential) throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        guard case .object(var members) = try JSONDecoder().decode(JSONValue.self, from: encoder.encode(credential))
        else { throw PassportError(.storageFailure, detail: "The credential could not be encoded.") }
        members["version"] = .number(Double(currentVersion))
        let output = JSONEncoder()
        output.outputFormatting = [.sortedKeys]
        return try output.encode(JSONValue.object(members))
    }

    /// Decodes a record written by ``encode(_:)``.
    ///
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/storageFailure`` for data that is
    /// not a credential record or has a version this library does not know.
    public static func decode(_ data: Data) throws -> Credential {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        do {
            let header = try decoder.decode(Header.self, from: data)
            guard header.version == currentVersion else {
                throw PassportError(.storageFailure, detail: "The stored credential has an unknown version.")
            }
            return try decoder.decode(Credential.self, from: data)
        } catch let error as PassportError {
            throw error
        } catch {
            throw PassportError(.storageFailure, detail: "The stored credential is malformed.")
        }
    }
}
