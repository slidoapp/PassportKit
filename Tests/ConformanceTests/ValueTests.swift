import Foundation
import PassportKit
import PassportKitTesting
import Testing

@Suite("Session value types")
struct ValueTests {
    static let canaries = ["canary-access-token", "canary-refresh-token", "canary-id-token", "canary-extra-field"]

    @Test("the built-in credential stores are static members of CredentialStore")
    func storeStaticMembers() async throws {
        let account = CredentialAccount(service: "com.example.app", account: "default")
        let credential = Credential(
            clientID: "app", refreshToken: Secret("rt"), updatedAt: Date(timeIntervalSince1970: 0))
        let memory: any CredentialStore = .inMemory(credentials: [account: credential])
        #expect(memory is InMemoryCredentialStore)
        #expect(try await memory.load(account) == credential)
        let keychain: any CredentialStore = .keychain(accessibility: .whenUnlockedThisDeviceOnly)
        #expect(keychain is KeychainCredentialStore)
    }

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
            updatedAt: Date(timeIntervalSince1970: 0))
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
            updatedAt: Date(timeIntervalSince1970: 1_700_000_000.5))
        let data = try credential.serializedData()
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(object["version"] as? Int == 1)
        #expect(object["refreshToken"] as? String == "rt")
        #expect(try Credential(serializedData: data) == credential)

        var future = object
        future["version"] = 2
        let error = #expect(throws: PassportError.self) {
            try Credential(serializedData: JSONSerialization.data(withJSONObject: future))
        }
        #expect(error?.code == .storageFailure)
        #expect(throws: PassportError.self) { try Credential(serializedData: Data("[]".utf8)) }

        // A record written by 0.3, which could carry application fields, still decodes; the fields are ignored.
        var older = object
        older["additionalFields"] = ["note": "x"]
        #expect(try Credential(serializedData: JSONSerialization.data(withJSONObject: older)) == credential)
    }

    @Test("a scope policy needs one of its scopes only for the targets it applies to")
    func requireAnyScope() async {
        let policy = RequireAnyScope(["read", "write"])
        let response = TokenResponse(accessToken: Secret("a"), tokenType: "Bearer")
        func verdict(_ target: TokenTarget, _ scope: ScopeSet?) async -> TokenAcceptance {
            await policy.evaluate(
                TokenAcceptanceContext(
                    token: AccessToken(value: Secret("a"), tokenType: "Bearer", grantedScope: scope, target: target),
                    response: response))
        }
        let resourceTarget = TokenTarget.refreshGrant(resources: [apiA])
        #expect(await verdict(resourceTarget, ["write", "other"]).isAccepted)
        #expect(await !verdict(resourceTarget, ["none"]).isAccepted)
        #expect(await !verdict(resourceTarget, nil).isAccepted, "an unknown scope proves nothing")
        #expect(await verdict(.default, ["none"]).isAccepted, "the default target is not selected")
    }

    @Test("events and requests are Hashable by value")
    func hashableValues() {
        let url = URL(string: "https://as.example.com/token")!
        let tokens = TokenResponse(accessToken: Secret("a"), tokenType: "Bearer", scope: ["read"])
        #expect(tokens == TokenResponse(accessToken: Secret("a"), tokenType: "Bearer", scope: ["read"]))
        #expect(tokens != TokenResponse(accessToken: Secret("b"), tokenType: "Bearer", scope: ["read"]))
        let authorization = AuthorizationRequest(redirectURI: url, prompt: [.login])
        #expect(Set([authorization, authorization]).count == 1)
        let exchange = TokenExchangeRequest(subjectToken: Secret("a"), subjectTokenType: .accessToken)
        #expect(Set([exchange, exchange]).count == 1)
        #expect(Set([OAuthSession.Event.signedIn, .signedIn, .storageFailed]).count == 2)
    }

    @Test("target selectors and closure policies")
    func selectorsAndClosures() async {
        let all = RequireAnyScope(["read"], for: .all)
        let named = RequireAnyScope(["read"], for: .matching { $0.scope == ["admin"] })
        let response = TokenResponse(accessToken: Secret("a"), tokenType: "Bearer")
        func context(_ target: TokenTarget) -> TokenAcceptanceContext {
            TokenAcceptanceContext(
                token: AccessToken(value: Secret("a"), tokenType: "Bearer", grantedScope: ["other"], target: target),
                response: response)
        }
        #expect(await !all.evaluate(context(.default)).isAccepted)
        #expect(await !named.evaluate(context(.refreshGrant(scope: ["admin"]))).isAccepted)
        #expect(await named.evaluate(context(.default)).isAccepted)
        let required: any TokenAcceptancePolicy = .requireAnyScope(["read"], for: .all)
        #expect(required is RequireAnyScope)
        #expect(await !required.evaluate(context(.default)).isAccepted)
        let anyToken: any TokenAcceptancePolicy = .acceptAnyToken
        #expect(anyToken is AcceptAnyToken)
        #expect(await anyToken.evaluate(context(.default)).isAccepted)
        let custom: any TokenAcceptancePolicy = .custom { $0.target == .default ? .reject(reason: "no") : .accept }
        #expect(await !custom.evaluate(context(.default)).isAccepted)
        #expect(await custom.evaluate(context(.refreshGrant(scope: ["admin"]))).isAccepted)
    }
}

extension TokenAcceptance {
    fileprivate var isAccepted: Bool {
        if case .accept = self { true } else { false }
    }
}
