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
    static let tokenURL = URL(string: "https://as.example.com/oauth/token")!
    static let deviceURL = URL(string: "https://as.example.com/oauth/device")!
    static let revocationURL = URL(string: "https://as.example.com/oauth/revoke")!

    static func configuration(
        authentication: ClientAuthentication = .none(clientID: "app"),
        additionalHeaders: HTTPHeaders = [:],
        revocation: Bool = true
    ) -> ClientConfiguration {
        ClientConfiguration(
            endpoints: Endpoints(
                token: tokenURL,
                deviceAuthorization: deviceURL,
                revocation: revocation ? revocationURL : nil
            ),
            authentication: authentication,
            additionalHeaders: additionalHeaders
        )
    }

    static func client(
        _ transport: any HTTPTransport,
        authentication: ClientAuthentication = .none(clientID: "app"),
        additionalHeaders: HTTPHeaders = [:],
        revocation: Bool = true,
        clock: any Clock<Duration> = ContinuousClock(),
        observer: (any PassportObserver)? = nil
    ) throws -> OAuthClient {
        try OAuthClient(
            configuration: configuration(
                authentication: authentication,
                additionalHeaders: additionalHeaders,
                revocation: revocation
            ),
            transport: transport,
            clock: clock,
            observer: observer
        )
    }
}
