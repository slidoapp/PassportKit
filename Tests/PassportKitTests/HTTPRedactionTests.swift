import Foundation
import Testing

@testable import PassportKit

struct HTTPRedactionTests {
    private let request = HTTPRequest(
        method: .post,
        url: URL(string: "https://user:pass@as.example.com/token?code=\(Canary.value)#frag")!,
        headers: ["Authorization": "Basic \(Canary.value)", "Content-Type": "application/x-www-form-urlencoded"],
        body: Data("refresh_token=\(Canary.value)".utf8)
    )

    @Test func requestNeverShowsBodyAuthorizationOrQuery() {
        for text in Canary.renderings(of: request) {
            #expect(!text.contains(Canary.value))
            #expect(!text.contains("user:pass"))
        }
        #expect(
            request.description
                == "HTTPRequest(POST https://as.example.com/token, headers: [\"Authorization\", \"Content-Type\"], body: 37 bytes)"
        )
    }

    @Test func responseNeverShowsBodyOrHeaderValues() {
        let response = HTTPResponse(
            statusCode: 200,
            headers: ["Set-Cookie": Canary.value],
            body: Data(#"{"access_token":"\#(Canary.value)"}"#.utf8)
        )
        for text in Canary.renderings(of: response) {
            #expect(!text.contains(Canary.value))
        }
        #expect(response.description.contains("status: 200"))
    }

    @Test func headersShowNamesOnly() {
        let headers: HTTPHeaders = ["Authorization": "Bearer \(Canary.value)", "Cookie": Canary.value]
        for text in Canary.renderings(of: headers) {
            #expect(!text.contains(Canary.value))
        }
        #expect(headers.description == "HTTPHeaders([\"Authorization\", \"Cookie\"])")
    }

    @Test func configurationNeverShowsHeaderValuesOrSecrets() {
        let configuration = ClientConfiguration(
            endpoints: Endpoints(token: URL(string: "https://as.example.com/token")!),
            authentication: .clientSecretBasic(clientID: "app", secret: Secret(Canary.value)),
            additionalHeaders: ["X-Api-Key": Canary.value]
        )
        for text in Canary.renderings(of: configuration) {
            #expect(!text.contains(Canary.value))
        }
    }
}
