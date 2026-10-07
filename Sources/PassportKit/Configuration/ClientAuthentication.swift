import Foundation

/// How the client authenticates at the token, device authorization and revocation endpoints.
///
/// Descriptions show the secret as `<redacted>` because ``Secret`` redacts itself.
public enum ClientAuthentication: Sendable, Hashable {
    /// A public client: sends `client_id` in the body (RFC 6749 §3.2.1).
    case none(clientID: String)
    /// Sends `client_id` and `client_secret` in the body (RFC 6749 §2.3.1).
    case clientSecretPost(clientID: String, secret: Secret)
    /// Sends HTTP Basic credentials; id and secret are form-encoded before base64 (RFC 6749 §2.3.1).
    case clientSecretBasic(clientID: String, secret: Secret)

    /// The `client_id`.
    public var clientID: String {
        switch self {
        case .none(let clientID), .clientSecretPost(let clientID, _), .clientSecretBasic(let clientID, _): clientID
        }
    }

    /// Adds the client credentials to a request being built: body parameters or the `Authorization` header.
    func apply(to parameters: inout [(String, String)], headers: inout HTTPHeaders) {
        switch self {
        case .none(let clientID):
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
