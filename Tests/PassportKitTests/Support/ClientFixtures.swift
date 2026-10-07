import Foundation

@testable import PassportKit

/// Test-only observer that keeps every event.
final class RecordingObserver: PassportObserver, @unchecked Sendable {
    // @unchecked Sendable: `stored` is only touched under `lock`.
    private let lock = NSLock()
    private var stored: [PassportEvent] = []

    var events: [PassportEvent] { lock.withLock { stored } }

    func record(_ event: PassportEvent) {
        lock.withLock { stored.append(event) }
    }
}

enum ClientFixtures {
    static let authorizationURL = URL(string: "https://as.example.com/oauth/authorize")!
    static let tokenURL = URL(string: "https://as.example.com/oauth/token")!
    static let deviceURL = URL(string: "https://as.example.com/oauth/device")!
    static let revocationURL = URL(string: "https://as.example.com/oauth/revoke")!

    static func configuration(
        authentication: ClientAuthentication = .publicClient(clientID: "app"),
        additionalHeaders: HTTPHeaders = [:],
        revocation: Bool = true,
        authorization: URL? = authorizationURL,
        issuer: URL? = nil,
        requiresIssuer: Bool = false
    ) -> ClientConfiguration {
        ClientConfiguration(
            endpoints: Endpoints(
                authorization: authorization,
                token: tokenURL,
                deviceAuthorization: deviceURL,
                revocation: revocation ? revocationURL : nil
            ),
            authentication: authentication,
            issuer: issuer,
            additionalHeaders: additionalHeaders,
            requiresIssuerInAuthorizationResponse: requiresIssuer
        )
    }

    static func client(
        _ transport: any HTTPTransport,
        authentication: ClientAuthentication = .publicClient(clientID: "app"),
        additionalHeaders: HTTPHeaders = [:],
        revocation: Bool = true,
        authorization: URL? = authorizationURL,
        issuer: URL? = nil,
        requiresIssuer: Bool = false,
        clock: any Clock<Duration> = ContinuousClock(),
        random: any RandomSource = SystemRandomSource(),
        observer: (any PassportObserver)? = nil
    ) throws -> OAuthClient {
        try OAuthClient(
            configuration: configuration(
                authentication: authentication,
                additionalHeaders: additionalHeaders,
                revocation: revocation,
                authorization: authorization,
                issuer: issuer,
                requiresIssuer: requiresIssuer
            ),
            transport: transport,
            clock: clock,
            random: random,
            observer: observer
        )
    }
}
