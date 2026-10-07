import Foundation
import PassportKit

struct DeviceRecord {
    enum Status {
        case pending
        case approved(subject: String)
        case denied
    }
    var clientID: String
    var userCode: String
    var scope: ScopeSet
    var resources: [URL]
    var expiresAt: Date
    var status = Status.pending
}

extension FakeAuthorizationServer {
    /// Approves the device authorization shown to the user as `userCode` (RFC 8628 §3.3).
    public func approve(userCode: String, subject: String = "user-1") throws {
        try updateDevice(userCode: userCode) { $0.status = .approved(subject: subject) }
    }

    /// Denies the device authorization; the next poll answers `access_denied`.
    public func deny(userCode: String) throws {
        try updateDevice(userCode: userCode) { $0.status = .denied }
    }

    /// Makes the next `times` device polls answer `slow_down` (RFC 8628 §3.5), before any other answer.
    public func requireSlowDown(times: Int) { slowDownsRemaining = times }

    private func updateDevice(userCode: String, _ update: (inout DeviceRecord) -> Void) throws {
        guard let name = devices.first(where: { $0.value.userCode == userCode })?.key else {
            throw ControlError(description: "No pending device authorization has this user code.")
        }
        update(&devices[name]!)
    }

    func handleDeviceAuthorization(_ request: RecordedRequest) throws -> HTTPResponse {
        let client = try authenticate(request)
        guard client.allowedGrants.contains(.deviceCode) else { throw Failure.oauth("unauthorized_client") }
        let scope = try requestedScope(request.value("scope"), client: client)
        let deviceCode = nextIdentifier("device")
        let userCode = nextIdentifier("USER").uppercased()
        devices[deviceCode] = DeviceRecord(
            clientID: client.id, userCode: userCode, scope: scope, resources: try resources(of: request),
            expiresAt: now().addingTimeInterval(controls.deviceCodeLifetime))
        return jsonResponse(
            200,
            [
                "device_code": deviceCode, "user_code": userCode,
                "verification_uri": "https://as.example.com/device",
                "verification_uri_complete": "https://as.example.com/device?user_code=\(userCode)",
                "expires_in": Int(controls.deviceCodeLifetime), "interval": controls.deviceInterval,
            ], headers: ["Cache-Control": "no-store"])
    }

    /// The device code grant at the token endpoint (RFC 8628 §3.4, §3.5).
    func pollDevice(_ request: RecordedRequest, client: ClientRegistration) throws -> HTTPResponse {
        guard let name = request.value("device_code"), let device = devices[name], device.clientID == client.id else {
            throw Failure.oauth("invalid_grant", "The device code is unknown or already used.")
        }
        guard device.expiresAt > now() else { throw Failure.oauth("expired_token") }
        if slowDownsRemaining > 0 {
            slowDownsRemaining -= 1
            throw Failure.oauth("slow_down")
        }
        switch device.status {
        case .pending: throw Failure.oauth("authorization_pending")
        case .denied: throw Failure.oauth("access_denied")
        case .approved(let subject):
            devices[name] = nil
            return issueNewGrant(
                client: client, subject: subject, scope: device.scope, resources: device.resources,
                withRefreshToken: true)
        }
    }
}
