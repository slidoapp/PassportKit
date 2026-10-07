import Foundation
import PassportKitTesting
import Testing

@testable import PassportKit

struct ClientAuthenticationTests {
    private func apply(_ authentication: ClientAuthentication) -> (parameters: [String], headers: HTTPHeaders) {
        var parameters: [(String, String)] = []
        var headers = HTTPHeaders()
        authentication.apply(to: &parameters, headers: &headers)
        return (parameters.map { "\($0.0)=\($0.1)" }, headers)
    }

    @Test func publicClientSendsClientIDInBody() {
        let result = apply(.none(clientID: "app"))
        #expect(result.parameters == ["client_id=app"])
        #expect(result.headers["Authorization"] == nil)
    }

    @Test func secretPostSendsBothInBody() {
        let result = apply(.clientSecretPost(clientID: "app", secret: Secret("s3cret")))
        #expect(result.parameters == ["client_id=app", "client_secret=s3cret"])
        #expect(result.headers["Authorization"] == nil)
    }

    @Test func basicFormEncodesBeforeBase64() throws {
        let result = apply(.clientSecretBasic(clientID: "my app:1", secret: Secret("p@ss+word/é&=~")))
        #expect(result.parameters.isEmpty)
        let header = try #require(result.headers["Authorization"])
        #expect(header.hasPrefix("Basic "))
        let decoded = try #require(Data(base64Encoded: String(header.dropFirst(6))))
        #expect(String(data: decoded, encoding: .utf8) == "my+app%3A1:p%40ss%2Bword%2F%C3%A9%26%3D~")
    }

    @Test func basicMatchesRFC2617Example() throws {
        // Plain alphanumerics are unchanged by form encoding.
        let result = apply(.clientSecretBasic(clientID: "Aladdin", secret: Secret("opensesame")))
        #expect(result.headers["Authorization"] == "Basic QWxhZGRpbjpvcGVuc2VzYW1l")
    }

    @Test func clientIDAccessor() {
        #expect(ClientAuthentication.none(clientID: "a").clientID == "a")
        #expect(ClientAuthentication.clientSecretPost(clientID: "b", secret: Secret("x")).clientID == "b")
        #expect(ClientAuthentication.clientSecretBasic(clientID: "c", secret: Secret("x")).clientID == "c")
    }

    @Test func descriptionsRedactTheSecret() {
        let authentication = ClientAuthentication.clientSecretPost(clientID: "app", secret: Secret(Canary.value))
        for text in Canary.renderings(of: authentication) {
            #expect(!text.contains(Canary.value))
        }
    }

    @Test(
        arguments: [
            ClientAuthentication.none(clientID: "app"),
            .clientSecretPost(clientID: "app", secret: Secret("s")),
            .clientSecretBasic(clientID: "app", secret: Secret("s")),
        ],
        ["client_id", "client_secret"]
    )
    func additionalParametersCannotAddASecondAuthenticationMethod(
        authentication: ClientAuthentication, name: String
    ) {
        let configuration = ClientFixtures.configuration(authentication: authentication)
        var request = FormRequest(tokenEndpoint: ClientFixtures.tokenURL, grantType: .clientCredentials)
        request.additionalParameters = [name: "other"]
        #expect {
            try request.build(configuration: configuration)
        } throws: { ($0 as? PassportError)?.code == .invalidConfiguration }
    }

    @Test func authorizationURLRejectsClientAuthenticationParameters() throws {
        let client = try ClientFixtures.client(RecordingTransport())
        let request = AuthorizationRequest(
            redirectURI: AuthorizationFixtures.redirectURI, additionalParameters: ["client_secret": "leak"])
        #expect {
            try client.beginAuthorization(request)
        } throws: { ($0 as? PassportError)?.code == .invalidConfiguration }
    }
}
