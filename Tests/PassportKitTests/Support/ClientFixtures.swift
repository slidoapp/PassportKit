import Foundation
import HTTPTypes
import os

@testable import PassportKit

/// Test-only observer that keeps every event.
final class RecordingObserver: PassportObserver, Sendable {
    private let stored = OSAllocatedUnfairLock(initialState: [PassportEvent]())

    var events: [PassportEvent] { stored.withLock { $0 } }

    func record(_ event: PassportEvent) {
        stored.withLock { $0.append(event) }
    }
}

enum ClientFixtures {
    static let authorizationURL = URL(string: "https://as.example.com/oauth/authorize")!
    static let tokenURL = URL(string: "https://as.example.com/oauth/token")!
    static let deviceURL = URL(string: "https://as.example.com/oauth/device")!
    static let revocationURL = URL(string: "https://as.example.com/oauth/revoke")!

    static func configuration(
        authentication: ClientAuthentication = .publicClient(clientID: "app"),
        additionalHeaders: HTTPFields = [:],
        revocation: Bool = true,
        authorization: URL? = authorizationURL,
        issuer: URL? = nil,
        requiresIssuer: Bool = false,
        allowsInsecureLoopback: Bool = false
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
            requiresIssuerInAuthorizationResponse: requiresIssuer,
            allowsInsecureLoopbackEndpoints: allowsInsecureLoopback
        )
    }

    static func client(
        _ transport: any HTTPTransport,
        authentication: ClientAuthentication = .publicClient(clientID: "app"),
        additionalHeaders: HTTPFields = [:],
        revocation: Bool = true,
        authorization: URL? = authorizationURL,
        issuer: URL? = nil,
        requiresIssuer: Bool = false,
        allowsInsecureLoopback: Bool = false,
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
                requiresIssuer: requiresIssuer,
                allowsInsecureLoopback: allowsInsecureLoopback
            ),
            transport: transport,
            clock: clock,
            random: random,
            observer: observer
        )
    }
}
