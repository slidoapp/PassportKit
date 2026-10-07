import PassportKit
import PassportKitTesting
import Testing

@Suite("TokenManager: a response without scope", .timeLimit(.minutes(1)))
struct OmittedScopeTests {
    @Test("RFC 6749 §6: a refresh without scope and a response without scope keep the originally granted scope")
    func refreshKeepsTheGrantedScope() async throws {
        let harness = try await Harness(policy: RequireAnyScope(["read"]), signedIn: false)
        await harness.server.configure { $0.omitsScope = true }
        try await harness.signInAgain()
        harness.expireAccessTokens()

        let token = try await harness.manager.accessToken()
        #expect(token.grantedScope == ["read", "write"])
    }

    @Test("a root refresh response that carries scope replaces the recorded grant scope")
    func rootRefreshRecordsTheReturnedScope() async throws {
        let harness = try await Harness(signedIn: true)
        await harness.server.configure { $0.scopePolicy = { _, _ in ["read"] } }
        harness.expireAccessTokens()
        #expect(try await harness.manager.accessToken().grantedScope == ["read"])
        #expect(await harness.manager.credential?.grantedScope == ["read"])
        #expect((try await harness.store.load(harness.account))?.grantedScope == ["read"])

        await harness.server.configure { $0.omitsScope = true }
        harness.expireAccessTokens()
        #expect(try await harness.manager.accessToken().grantedScope == ["read"])
    }

    @Test("a refresh for a narrower scope does not change the recorded grant scope")
    func narrowedTargetKeepsTheRecordedScope() async throws {
        let harness = try await Harness()
        let token = try await harness.manager.accessToken(for: .refreshGrant(scope: ["read"]))
        #expect(token.grantedScope == ["read"])
        #expect(await harness.manager.credential?.grantedScope == ["read", "write"])
    }
}
