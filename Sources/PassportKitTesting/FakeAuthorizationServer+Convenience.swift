import Foundation
import PassportKit

extension FakeAuthorizationServer {
    /// A client for the registered `clientID` that talks to this server.
    ///
    /// The endpoints, the issuer and the client authentication (public, or `client_secret_post` when the
    /// registration has a secret) come from the server. `wallClock` and `clock` default to the server's own, so
    /// token expiry and delays agree; pass others to move the client's time separately.
    ///
    /// Throws ``ControlError`` when no client with that identifier is registered.
    public func makeClient(
        clientID: String,
        wallClock: (any WallClock)? = nil,
        clock: (any Clock<Duration>)? = nil
    ) throws -> OAuthClient {
        guard let registration = clients[clientID] else {
            throw ControlError(description: "The client is not registered.")
        }
        let authentication: ClientAuthentication =
            registration.secret.map { .clientSecretPost(clientID: clientID, secret: $0) }
            ?? .publicClient(clientID: clientID)
        let configuration = ClientConfiguration(
            endpoints: Endpoints(
                authorization: Self.authorizationEndpoint,
                token: Self.tokenEndpoint,
                deviceAuthorization: Self.deviceAuthorizationEndpoint,
                revocation: Self.revocationEndpoint),
            authentication: authentication,
            issuer: Self.issuer)
        return try OAuthClient(
            configuration: configuration, transport: self, wallClock: wallClock ?? self.wallClock,
            clock: clock ?? self.clock)
    }

    /// A user agent that plays the user: it sends each authorization request to this server and returns the
    /// callback, so `OAuthClient.authorize(_:using:)` runs a whole sign-in without a browser.
    public nonisolated func userAgent(
        subject: String = "user-1",
        decision: Decision = .approve
    ) -> any AuthorizationUserAgent {
        SimulatedUserAgent(server: self, subject: subject, decision: decision)
    }
}

private struct SimulatedUserAgent: AuthorizationUserAgent {
    let server: FakeAuthorizationServer
    let subject: String
    let decision: FakeAuthorizationServer.Decision

    func present(_ url: URL, redirectURI: URL) async throws -> URL {
        try await server.authorizeInteractively(url, subject: subject, decision: decision)
    }
}
