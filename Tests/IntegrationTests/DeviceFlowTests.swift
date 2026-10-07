import Foundation
import PassportKit
import Testing

/// The server's device interval is 5 s and the tests use the real clock, so each takes a little over 5 s.
@Suite(
    "Device authorization flow",
    .enabled(if: IntegrationServer.isConfigured, "Set PASSPORTKIT_INTEGRATION_ISSUER or run `make integration`."),
    .timeLimit(.minutes(1))
)
struct DeviceFlowTests {
    @Test func approvedDeviceFlowSignsIn() async throws {
        let client = try await IntegrationServer.client()
        let authorization = try await client.startDeviceAuthorization(scope: IntegrationServer.fullScope)
        #expect(authorization.interval == .seconds(5))

        async let approval: Void = IntegrationServer.decideDevice(userCode: authorization.userCode, approve: true)
        let response = try await client.completeDeviceAuthorization(authorization)
        try await approval

        let account = CredentialAccount(service: "IntegrationTests.\(UUID())", account: "user")
        let manager = TokenManager(client: client, store: InMemoryCredentialStore(), account: account)
        try await manager.signIn(with: response, requestedScope: IntegrationServer.fullScope)
        let token = try await manager.accessToken()
        #expect(token.grantedScope?.contains("api:read") == true)
        #expect(await manager.credential?.refreshToken != nil)
    }

    @Test func deniedDeviceFlowEndsWithAccessDenied() async throws {
        let client = try await IntegrationServer.client()
        let authorization = try await client.startDeviceAuthorization(scope: IntegrationServer.fullScope)

        async let decision: Void = IntegrationServer.decideDevice(userCode: authorization.userCode, approve: false)
        let error = await passportError { _ = try await client.completeDeviceAuthorization(authorization) }
        try await decision

        #expect(error?.code == .accessDenied)
        #expect(error?.recovery == PassportError.Recovery.none)
    }
}
