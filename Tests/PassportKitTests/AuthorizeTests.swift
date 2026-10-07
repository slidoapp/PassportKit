import Foundation
import PassportKitTesting
import Testing

@testable import PassportKit

@Suite(.timeLimit(.minutes(1)))
struct AuthorizeTests {
    @Test func authorizePresentsTheURLAndRedeemsTheCallback() async throws {
        let transport = RecordingTransport([.tokens("granted")])
        let client = try ClientFixtures.client(transport, random: CountingRandomSource())
        let agent = FakeUserAgent(
            .callback { url in
                AuthorizationFixtures.callback(
                    [("code", "abc"), ("state", AuthorizationFixtures.state(of: url))],
                    to: AuthorizationFixtures.redirectURI)
            })
        let response = try await client.authorize(
            AuthorizationRequest(redirectURI: AuthorizationFixtures.redirectURI, scope: ["openid"]), using: agent)
        #expect(response.accessToken.reveal() == "granted")
        let shown = try #require(await agent.presented.first)
        #expect(shown.redirectURI == AuthorizationFixtures.redirectURI)
        #expect(shown.url.absoluteString.hasPrefix(ClientFixtures.authorizationURL.absoluteString + "?"))
        let sent = try #require(await transport.requests.first)
        #expect(sent.value("code") == "abc")
        #expect(sent.value("code_verifier") == CountingRandomSource.text(call: 2))
    }

    @Test func userCancellationPropagatesWithoutATokenRequest() async throws {
        let transport = RecordingTransport()
        let client = try ClientFixtures.client(transport)
        let agent = FakeUserAgent(.fail(PassportError(.userCancelled)))
        let error = try await #require(throws: PassportError.self) {
            try await client.authorize(
                AuthorizationRequest(redirectURI: AuthorizationFixtures.redirectURI), using: agent)
        }
        #expect(error.code == .userCancelled)
        #expect(await transport.requests.isEmpty)
    }

    @Test func aForgedCallbackFromTheAgentIsRejected() async throws {
        let transport = RecordingTransport()
        let client = try ClientFixtures.client(transport)
        let agent = FakeUserAgent(
            .callback { _ in AuthorizationFixtures.callback([("code", "abc"), ("state", "forged")]) })
        let error = try await #require(throws: PassportError.self) {
            try await client.authorize(
                AuthorizationRequest(redirectURI: AuthorizationFixtures.redirectURI), using: agent)
        }
        #expect(error.code == .stateMismatch)
        #expect(await transport.requests.isEmpty)
    }

    @Test func configurationMistakesSurfaceBeforeTheAgentIsInvoked() async throws {
        let client = try ClientFixtures.client(RecordingTransport(), authorization: nil)
        let agent = FakeUserAgent(.fail(PassportError(.userCancelled)))
        let error = try await #require(throws: PassportError.self) {
            try await client.authorize(
                AuthorizationRequest(redirectURI: AuthorizationFixtures.redirectURI), using: agent)
        }
        #expect(error.code == .invalidConfiguration)
        #expect(await agent.presented.isEmpty)
    }
}
