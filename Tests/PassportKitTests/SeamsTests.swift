import Foundation
import Testing

@testable import PassportKit

struct SeamsTests {
    @Test func systemRandomSourceReturnsRequestedCount() {
        let source = SystemRandomSource()
        #expect(source.bytes(count: 0).isEmpty)
        #expect(source.bytes(count: 32).count == 32)
        #expect(source.bytes(count: 32) != source.bytes(count: 32))
    }

    @Test func systemWallClockIsCurrent() {
        let before = Date()
        let now = SystemWallClock().now()
        #expect(now >= before && now.timeIntervalSince(before) < 5)
    }

    @Test func grantAndTokenTypeIdentifiers() throws {
        #expect(GrantType.deviceCode.rawValue == "urn:ietf:params:oauth:grant-type:device_code")
        #expect(GrantType.tokenExchange.rawValue == "urn:ietf:params:oauth:grant-type:token-exchange")
        #expect(TokenTypeIdentifier.refreshToken.rawValue == "urn:ietf:params:oauth:token-type:refresh_token")
        let encoded = try JSONEncoder().encode([GrantType.refreshToken])
        #expect(String(data: encoded, encoding: .utf8) == #"["refresh_token"]"#)
        #expect(try JSONDecoder().decode([GrantType].self, from: encoded) == [.refreshToken])
        #expect(
            try JSONDecoder().decode([TokenTypeIdentifier].self, from: Data(#"["custom"]"#.utf8)).first?.rawValue
                == "custom")
        #expect(TokenTypeHint.refreshToken.rawValue == "refresh_token")
    }
}
