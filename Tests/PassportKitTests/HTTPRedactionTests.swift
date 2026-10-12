import Foundation
import HTTPTypes
import PassportKitTesting
import Testing

@testable import PassportKit

struct HTTPRedactionTests {
    private let request = HTTPRequest(
        method: .post,
        url: URL(string: "https://user:pass@as.example.com/token?code=\(Canary.value)#frag")!,
        headerFields: [.authorization: "Basic \(Canary.value)", .contentType: "application/x-www-form-urlencoded"]
    )

    @Test func configurationNeverShowsHeaderValuesOrSecrets() {
        let configuration = ClientConfiguration(
            endpoints: Endpoints(token: URL(string: "https://as.example.com/token")!),
            authentication: .clientSecretBasic(clientID: "app", secret: Secret(Canary.value)),
            additionalHeaders: [HTTPField.Name("X-Api-Key")!: Canary.value]
        )
        for text in Canary.renderings(of: configuration) {
            #expect(!text.contains(Canary.value))
        }
        #expect(configuration.description.contains("X-Api-Key"))
    }

    @Test func recordedRequestNeverShowsBodyHeaderValuesOrQuery() {
        let recorded = RecordedRequest(request, body: Data("refresh_token=\(Canary.value)".utf8))
        for text in Canary.renderings(of: recorded) {
            #expect(!text.contains(Canary.value))
            #expect(!text.contains("user:pass"))
        }
        #expect(
            recorded.description
                == "RecordedRequest(POST https://as.example.com/token, headers: [\"Authorization\", \"Content-Type\"], body: 37 bytes)"
        )
    }

    @Test func scriptedResponsesNeverShowBodyOrHeaderValues() {
        let response = HTTPResponse(status: .ok, headerFields: [.setCookie: Canary.value])
        let body = Data(#"{"access_token":"\#(Canary.value)"}"#.utf8)
        for value in [
            RecordingTransport.Step.respond(response, body: body) as Any,
            FakeAuthorizationServer.ResponseOverride(status: 200, body: String(decoding: body, as: UTF8.self)) as Any,
        ] {
            for text in Canary.renderings(of: value) {
                #expect(!text.contains(Canary.value))
            }
        }
        #expect(RecordingTransport.Step.respond(response, body: body).description.contains("status: 200"))
    }

    @Test func sensitiveFieldsAreNeverIndexed() {
        var fields: HTTPFields = [.authorization: "stale"]
        fields.setSensitive(.authorization, "Bearer token")
        #expect(fields[values: .authorization] == ["Bearer token"])
        #expect(fields.first?.indexingStrategy == .disallow)
    }

    @Test func targetsDropUserinfoQueryAndFragment() {
        let url = URL(string: "https://user:pass@as.example.com:8443/cb?code=\(Canary.value)#frag")!
        #expect(url.redactedTarget == "https://as.example.com:8443/cb")
    }
}
