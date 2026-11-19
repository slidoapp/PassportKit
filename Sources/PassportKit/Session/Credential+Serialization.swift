import Foundation

// The versioned JSON record of a stored credential, for `CredentialStore` implementations that write bytes.
extension Credential {
    /// The record version written by ``serializedData()``.
    static let recordVersion = 1

    private struct RecordHeader: Decodable {
        var version: Int
    }

    /// Encodes the credential as a version 1 record: its members next to `"version": 1`, with sorted keys.
    ///
    /// Token values appear as plain strings, so the returned bytes are secrets and belong in protected storage only.
    public func serializedData() throws -> Data {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        guard case .object(var members) = try JSONDecoder().decode(JSONValue.self, from: encoder.encode(self))
        else { throw PassportError(.storageFailure, detail: "The credential could not be encoded.") }
        members["version"] = .number(Double(Self.recordVersion))
        let output = JSONEncoder()
        output.outputFormatting = [.sortedKeys]
        return try output.encode(JSONValue.object(members))
    }

    /// Decodes a record written by ``serializedData()``.
    ///
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/storageFailure`` for data that is
    /// not a credential record or has a version this library does not know.
    public init(serializedData data: Data) throws {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        do {
            let header = try decoder.decode(RecordHeader.self, from: data)
            guard header.version == Self.recordVersion else {
                throw PassportError(.storageFailure, detail: "The stored credential has an unknown version.")
            }
            self = try decoder.decode(Credential.self, from: data)
        } catch let error as PassportError {
            throw error
        } catch {
            throw PassportError(.storageFailure, detail: "The stored credential is malformed.")
        }
    }
}
