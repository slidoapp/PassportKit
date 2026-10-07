import Foundation
import Testing

@testable import PassportKit

struct AdditionalParametersTests {
    @Test func preservesOrderAndDuplicates() {
        var parameters: AdditionalParameters = ["b": "1", "a": "2", "b": "3"]
        parameters.append("a", "4")
        #expect(parameters.items.map(\.name) == ["b", "a", "b", "a"])
        #expect(parameters.items.map(\.value) == ["1", "2", "3", "4"])
    }

    @Test func appendsAfterStandardParameters() throws {
        let parameters: AdditionalParameters = ["x": "1", "x": "2"]
        let merged = try parameters.appending(to: [("grant_type", "refresh_token"), ("refresh_token", "r")])
        #expect(merged.map { "\($0.0)=\($0.1)" } == ["grant_type=refresh_token", "refresh_token=r", "x=1", "x=2"])
    }

    @Test func collisionWithStandardParameterThrows() {
        let parameters: AdditionalParameters = ["scope": "x"]
        #expect {
            try parameters.appending(to: [("grant_type", "g"), ("scope", "s")])
        } throws: { error in
            let error = error as? PassportError
            return error?.code == .invalidConfiguration && error?.recovery == .fixConfiguration
        }
    }

    @Test func collisionIsCaseSensitive() throws {
        let parameters: AdditionalParameters = ["Scope": "x"]
        #expect(try parameters.appending(to: [("scope", "s")]).count == 2)
    }

    @Test func descriptionsShowNamesOnly() {
        let parameters: AdditionalParameters = ["assertion": Canary.value]
        for text in Canary.renderings(of: parameters) {
            #expect(!text.contains(Canary.value))
        }
    }
}
