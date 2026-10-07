import Foundation
import PassportKit
import PassportKitTesting
import Testing

/// A policy that never answers for targets with resources, until its gate opens.
struct HangingPolicy: TokenAcceptancePolicy {
    let gate: Gate

    func evaluate(_ context: TokenAcceptanceContext) async -> TokenAcceptance {
        if !context.target.resources.isEmpty { await gate.wait() }
        return .accept
    }
}

@Suite("TokenManager: acceptance policy time limit and rejected tokens", .timeLimit(.minutes(1)))
struct AcceptanceTests {
    @Test("invariant 4: a policy that never answers rejects the token and does not wedge the session")
    func hungPolicy() async throws {
        let gate = Gate()
        let harness = try await Harness(policy: HangingPolicy(gate: gate))
        let manager = harness.manager
        let target = TokenTarget.refreshGrant(resources: [apiA])
        let hanging = Task { try await manager.accessToken(for: target) }
        #expect(await harness.clock.waitForSleeper(timeout: .seconds(2)), "the policy has no time limit")
        harness.clock.advance(by: .seconds(10))
        let isDone = await finishes(hanging)
        gate.open()
        #expect(isDone, "a hung policy held the flight")
        let error = await thrownError { try await hanging.value }
        #expect(error?.code == .tokenRejected)
        #expect(error?.recovery == .resourceDenied)

        // The session and its lane are intact: the next refresh goes through on the rotated refresh token.
        #expect(await harness.manager.credential != nil)
        harness.expireAccessTokens()
        _ = try await manager.accessToken()
        let presented = await harness.presentedRefreshTokens()
        #expect(presented.count == 2 && Set(presented).count == 2)
    }

    @Test("invariant 4: a rejected token is not requested again for a while, and the rotated token is not wasted")
    func rejectionIsRemembered() async throws {
        let harness = try await Harness(policy: RequireAnyScope(["read"]))
        let manager = harness.manager
        await harness.server.configure { $0.isResourceUnauthorized = { $0.path.hasPrefix("/denied") } }
        let denied = TokenTarget.refreshGrant(resources: [deniedResource])

        let first = await thrownError { try await manager.accessToken(for: denied) }
        #expect(first?.code == .tokenRejected)
        for _ in 0..<5 {
            let again = await thrownError { try await manager.accessToken(for: denied) }
            #expect(again?.code == .tokenRejected && again?.recovery == .resourceDenied)
        }
        #expect(await harness.tokenRequests(.refreshToken).count == 1, "retrying caused a refresh storm")
        // Other targets are not affected, and no further rejection was reported.
        _ = try await manager.accessToken(for: TokenTarget.refreshGrant(resources: [apiA]))
        _ = await manager.signOut(revoke: false)
        #expect(
            await Harness.take(4, from: harness.events) == [
                .signedIn, .tokenRejected(target: denied, grantedScope: ["none"]),
                .refreshed(target: TokenTarget.refreshGrant(resources: [apiA])), .signedOut(reason: .userInitiated),
            ])

        // After the window the server is asked again.
        let later = try await Harness(policy: RequireAnyScope(["read"]))
        await later.server.configure { $0.isResourceUnauthorized = { $0.path.hasPrefix("/denied") } }
        _ = await thrownError { try await later.manager.accessToken(for: denied) }
        later.wallClock.advance(by: .seconds(31))
        _ = await thrownError { try await later.manager.accessToken(for: denied) }
        #expect(await later.tokenRequests(.refreshToken).count == 2)
    }

    @Test("invariant 4: signing in again, and invalidate, forget a rejection; a zero duration disables it")
    func rejectionIsForgotten() async throws {
        let denied = TokenTarget.refreshGrant(resources: [deniedResource])
        let harness = try await Harness(policy: RequireAnyScope(["read"]))
        await harness.server.configure { $0.isResourceUnauthorized = { $0.path.hasPrefix("/denied") } }
        _ = await thrownError { try await harness.manager.accessToken(for: denied) }
        _ = await thrownError { try await harness.manager.accessToken(for: denied) }
        #expect(await harness.tokenRequests(.refreshToken).count == 1)

        await harness.manager.invalidate(AccessToken(value: Secret("unused"), tokenType: "Bearer", target: denied))
        _ = await thrownError { try await harness.manager.accessToken(for: denied) }
        #expect(await harness.tokenRequests(.refreshToken).count == 2)

        try await harness.signInAgain()
        _ = await thrownError { try await harness.manager.accessToken(for: denied) }
        #expect(await harness.tokenRequests(.refreshToken).count == 3)

        let uncached = try await Harness(policy: RequireAnyScope(["read"]), rejectedTokenCacheDuration: .zero)
        await uncached.server.configure { $0.isResourceUnauthorized = { $0.path.hasPrefix("/denied") } }
        _ = await thrownError { try await uncached.manager.accessToken(for: denied) }
        _ = await thrownError { try await uncached.manager.accessToken(for: denied) }
        #expect(await uncached.tokenRequests(.refreshToken).count == 2)
    }

    enum Rejection: CaseIterable { case invalidTarget, invalidScope }

    @Test(
        "invariant 5: invalid_target and invalid_scope for a narrowed refresh are resource-level and keep the session",
        arguments: Rejection.allCases)
    func narrowedRefreshRejected(rejection: Rejection) async throws {
        let harness = try await Harness()
        await harness.server.configure {
            $0.isResourceUnauthorized = { $0.path.hasPrefix("/denied") }
            $0.refreshWithUnauthorizedResource = .invalidTarget400
        }
        let target =
            switch rejection {
            case .invalidTarget: TokenTarget.refreshGrant(resources: [deniedResource])
            case .invalidScope: TokenTarget.refreshGrant(scope: ["admin"])
            }
        let before = await harness.storedRefreshToken()
        let error = await thrownError { try await harness.manager.accessToken(for: target) }
        #expect(error?.code == (rejection == .invalidTarget ? .invalidTarget : .invalidScope))
        #expect(error?.recovery != .reauthenticate)
        #expect(await harness.manager.credential != nil)
        #expect(await harness.storedRefreshToken() == before)
        harness.expireAccessTokens()
        _ = try await harness.manager.accessToken()
    }

    @Test("invariant 5: invalid_grant for a narrowed refresh means the refresh token is rejected and ends the session")
    func invalidGrantOfNarrowedRefresh() async throws {
        let harness = try await Harness()
        await harness.server.configure {
            $0.override = {
                $0.value("resource") != nil ? .init(status: 400, body: #"{"error":"invalid_grant"}"#) : nil
            }
        }
        let error = await thrownError {
            try await harness.manager.accessToken(for: TokenTarget.refreshGrant(resources: [apiA]))
        }
        #expect(error?.recovery == .reauthenticate)
        #expect(await harness.manager.credential == nil)
    }
}
