import Foundation
import Testing

@testable import PassportKit

struct TokenResponseTests {
    private func parse(_ json: String) throws -> TokenResponse {
        try TokenResponse(parsing: Data(json.utf8))
    }

    @Test func parsesFullResponse() throws {
        let response = try parse(
            """
            {"access_token":"at","token_type":"Bearer","expires_in":3600,"refresh_token":"rt","id_token":"it",
             "scope":"b a","issued_token_type":"urn:ietf:params:oauth:token-type:access_token"}
            """
        )
        #expect(response.accessToken.reveal() == "at")
        #expect(response.tokenType == "Bearer")
        #expect(response.expiresIn == .seconds(3600))
        #expect(response.refreshToken?.reveal() == "rt")
        #expect(response.idToken?.reveal() == "it")
        #expect(response.scope == ["a", "b"])
        #expect(response.issuedTokenType == .accessToken)
        #expect(response.additionalFields.isEmpty)
    }

    @Test(arguments: [
        (#"3600"#, Duration?.some(.seconds(3600))),
        (#""3600""#, .some(.seconds(3600))),
        (#""3600.5""#, .some(.seconds(3600.5))),
        (#"3600.5"#, .some(.seconds(3600.5))),
        (#""soon""#, nil),
        (#""""#, nil),
        (#"null"#, nil),
        (#"true"#, nil),
        (#"-5"#, .some(.zero)),
        (#"1e30"#, .some(.seconds(3_153_600_000))),
    ])
    func expiresIn(raw: String, expected: Duration?) throws {
        let response = try parse(#"{"access_token":"at","token_type":"bearer","expires_in":\#(raw)}"#)
        #expect(response.expiresIn == expected)
    }

    @Test func missingExpiresInIsNil() throws {
        #expect(try parse(#"{"access_token":"at","token_type":"Bearer"}"#).expiresIn == nil)
    }

    @Test(arguments: ["Bearer", "bearer", "BEARER", "bEaReR"])
    func tokenTypeIsCaseInsensitive(tokenType: String) throws {
        let response = try parse(#"{"access_token":"at","token_type":"\#(tokenType)"}"#)
        #expect(response.isBearer)
        #expect(response.tokenType == tokenType)
    }

    @Test func otherTokenTypesAreNotBearer() throws {
        #expect(try !parse(#"{"access_token":"at","token_type":"N_A"}"#).isBearer)
    }

    @Test(arguments: [
        #"{"token_type":"Bearer"}"#,
        #"{"access_token":"","token_type":"Bearer"}"#,
        #"{"access_token":null,"token_type":"Bearer"}"#,
        #"{"access_token":5,"token_type":"Bearer"}"#,
        #"{"access_token":"at"}"#,
        #"{"access_token":"at","token_type":""}"#,
        #"{"access_token":"at","token_type":7}"#,
        #"[]"#,
        #""at""#,
        #"not json"#,
        #""#,
    ])
    func rejectsInvalidResponses(json: String) {
        #expect {
            try parse(json)
        } throws: { error in
            (error as? PassportError)?.code == .invalidResponse
        }
    }

    @Test func preservesUnknownFields() throws {
        let response = try parse(
            #"{"access_token":"at","token_type":"Bearer","ext_expires_in":10,"flags":[true,null],"meta":{"k":"v"}}"#
        )
        #expect(
            response.additionalFields == [
                "ext_expires_in": .number(10), "flags": .array([.bool(true), .null]),
                "meta": .object(["k": .string("v")]),
            ]
        )
    }

    @Test func nullKnownMembersAreAbsentAndWrongTypesAreKept() throws {
        let response = try parse(
            #"{"access_token":"at","token_type":"Bearer","refresh_token":null,"scope":["a"],"id_token":""}"#
        )
        #expect(response.refreshToken == nil)
        #expect(response.idToken == nil)
        #expect(response.scope == nil)
        #expect(response.additionalFields == ["scope": .array([.string("a")])])
    }

    @Test func scopeOmittedVersusPresent() throws {
        let omitted = try parse(#"{"access_token":"at","token_type":"Bearer"}"#)
        let present = try parse(#"{"access_token":"at","token_type":"Bearer","scope":"read"}"#)
        let empty = try parse(#"{"access_token":"at","token_type":"Bearer","scope":""}"#)
        #expect(omitted.scope == nil)
        #expect(present.scope == ["read"])
        #expect(empty.scope == [])
        #expect(omitted.grantedScope(requested: ["a", "b"]) == ["a", "b"])
        #expect(omitted.grantedScope(requested: nil) == nil)
        #expect(present.grantedScope(requested: ["a", "b"]) == ["read"])
        #expect(empty.grantedScope(requested: ["a"]) == [])
    }

    @Test func descriptionsNeverShowSecretsOrExtraFieldValues() throws {
        let response = try parse(
            """
            {"access_token":"\(Canary.value)","token_type":"Bearer","refresh_token":"\(Canary.value)",
             "id_token":"\(Canary.value)","vendor_secret":"\(Canary.value)"}
            """
        )
        for text in Canary.renderings(of: response) {
            #expect(!text.contains(Canary.value))
        }
        #expect(response.description.contains("vendor_secret"))
    }
}
