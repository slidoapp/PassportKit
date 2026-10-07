import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("Session value types")
struct ValueTests {
    static let canaries = ["canary-access-token", "canary-refresh-token", "canary-id-token", "canary-extra-field"]

    @Test("a DeviceAuthorization can be created for previews and keeps its device code private")
    func deviceAuthorizationForPreviews() {
        let clock = ManualClock()
        let authorization = DeviceAuthorization(
            deviceCode: Secret(Self.canaries[1]), userCode: "ABCD-EFGH",
            verificationURI: URL(string: "https://as.example.com/device")!, expiresIn: .seconds(600),
            expiresAt: Date(timeIntervalSince1970: 600), clock: clock)
        clock.advance(by: .seconds(100))
        #expect(authorization.remainingLifetime == .seconds(500))
        #expect(authorization.interval == .seconds(5))
        var dumped = ""
        dump(authorization, to: &dumped)
        for output in [authorization.description, dumped] { #expect(!output.contains(Self.canaries[1])) }
    }

    @Test("descriptions and reflection of AccessToken and Credential never show secrets")
    func redaction() {
        let token = AccessToken(
            value: Secret(Self.canaries[0]), tokenType: "Bearer", grantedScope: ["read"],
            additionalFields: ["extra": .string(Self.canaries[3])])
        let credential = Credential(
            clientID: "app", refreshToken: Secret(Self.canaries[1]), idToken: Secret(Self.canaries[2]),
            updatedAt: Date(timeIntervalSince1970: 0), additionalFields: ["extra": .string(Self.canaries[3])])
        var outputs: [String] = []
        outputs += [String(describing: token), String(reflecting: token), "\(token)"]
        outputs += [String(describing: credential), String(reflecting: credential), "\(credential)"]
        var dumped = ""
        dump(token, to: &dumped)
        dump(credential, to: &dumped)
        outputs.append(dumped)
        for output in outputs {
            for canary in Self.canaries { #expect(!output.contains(canary)) }
        }
        #expect(token.description.contains("<redacted>"))
        #expect(credential.description.contains("clientID: app"))
    }

    @Test("stored credentials are versioned JSON and round trip")
    func coding() throws {
        let credential = Credential(
            clientID: "app", issuer: URL(string: "https://as.example.com"), refreshToken: Secret("rt"),
            idToken: Secret("id"), grantedScope: ["read", "write"],
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000.5),
            additionalFields: ["note": .string("x")])
        let data = try CredentialCoding.encode(credential)
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(object["version"] as? Int == 1)
        #expect(object["refreshToken"] as? String == "rt")
        #expect(try CredentialCoding.decode(data) == credential)

        var future = object
        future["version"] = 2
        let error = #expect(throws: PassportError.self) {
            try CredentialCoding.decode(JSONSerialization.data(withJSONObject: future))
        }
        #expect(error?.code == .storageFailure)
        #expect(throws: PassportError.self) { try CredentialCoding.decode(Data("[]".utf8)) }
    }

    @Test("a scope policy needs one of its scopes only for the targets it applies to")
    func requireAnyScope() async {
        let policy = RequireAnyScope(["read", "write"])
        let response = TokenResponse(accessToken: Secret("a"), tokenType: "Bearer")
        func verdict(_ target: TokenTarget, _ scope: ScopeSet?) async -> TokenAcceptance {
            await policy.evaluate(
                AccessToken(value: Secret("a"), tokenType: "Bearer", grantedScope: scope, target: target),
                response: response)
        }
        let resourceTarget = TokenTarget.refreshGrant(resources: [apiA])
        #expect(await verdict(resourceTarget, ["write", "other"]).isAccepted)
        #expect(await !verdict(resourceTarget, ["none"]).isAccepted)
        #expect(await !verdict(resourceTarget, nil).isAccepted, "an unknown scope proves nothing")
        #expect(await verdict(.default, ["none"]).isAccepted, "the default target is not selected")
    }
}

extension TokenAcceptance {
    fileprivate var isAccepted: Bool {
        if case .accept = self { true } else { false }
    }
}
