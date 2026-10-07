import Foundation

/// How the client authenticates at the token, device authorization and revocation endpoints.
///
/// An open set: new methods can be added without breaking source compatibility. Create a value with one of the
/// static factories. Descriptions show the secret as `<redacted>` because ``Secret`` redacts itself.
public struct ClientAuthentication: Sendable, Hashable {
    enum Storage: Sendable, Hashable {
        case publicClient(clientID: String)
        case clientSecretPost(clientID: String, secret: Secret)
        case clientSecretBasic(clientID: String, secret: Secret)
    }

    let storage: Storage

    private init(_ storage: Storage) {
        self.storage = storage
    }

    /// A public client: sends `client_id` in the body (RFC 6749 §3.2.1).
    public static func publicClient(clientID: String) -> ClientAuthentication {
        ClientAuthentication(.publicClient(clientID: clientID))
    }

    /// Sends `client_id` and `client_secret` in the body (RFC 6749 §2.3.1).
    public static func clientSecretPost(clientID: String, secret: Secret) -> ClientAuthentication {
        ClientAuthentication(.clientSecretPost(clientID: clientID, secret: secret))
    }

    /// Sends HTTP Basic credentials; id and secret are form-encoded before base64 (RFC 6749 §2.3.1).
    public static func clientSecretBasic(clientID: String, secret: Secret) -> ClientAuthentication {
        ClientAuthentication(.clientSecretBasic(clientID: clientID, secret: secret))
    }

    /// The `client_id`.
    public var clientID: String {
        switch storage {
        case .publicClient(let clientID), .clientSecretPost(let clientID, _), .clientSecretBasic(let clientID, _):
            clientID
        }
    }

    /// The client secret, when the method has one.
    var secret: Secret? {
        switch storage {
        case .publicClient: nil
        case .clientSecretPost(_, let secret), .clientSecretBasic(_, let secret): secret
        }
    }

    /// The parameter names that carry client authentication. They are reserved in every mode, so an additional
    /// parameter can never add a second authentication method (RFC 6749 §2.3).
    static let parameterNames: Set<String> = ["client_id", "client_secret"]

    /// Adds the client credentials to a request being built: body parameters or the `Authorization` header.
    func apply(to parameters: inout [(String, String)], headers: inout HTTPHeaders) {
        switch storage {
        case .publicClient(let clientID):
            parameters.append(("client_id", clientID))
        case .clientSecretPost(let clientID, let secret):
            parameters.append(("client_id", clientID))
            parameters.append(("client_secret", secret.reveal()))
        case .clientSecretBasic(let clientID, let secret):
            let credentials =
                FormEncoding.encodeComponent(clientID) + ":" + FormEncoding.encodeComponent(secret.reveal())
            headers["Authorization"] = "Basic " + Data(credentials.utf8).base64EncodedString()
        }
    }
}
