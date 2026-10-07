#if canImport(Network)
    import Foundation
    import Testing

    @testable import PassportKitApple

    @Suite("Loopback request parsing")
    struct LoopbackRequestHeadTests {
        private func parse(_ text: String) -> LoopbackRequestHead.Outcome {
            LoopbackRequestHead.parse(Data(text.utf8))
        }

        @Test func parsesRequestLineAndHeaders() {
            let outcome = parse(
                "GET /callback?code=abc&state=xyz HTTP/1.1\r\nHost: 127.0.0.1:5000\r\nAccept: */*\r\n\r\n")
            guard case .complete(let head) = outcome else {
                Issue.record("expected a complete head")
                return
            }
            #expect(head.method == "GET")
            #expect(head.target == "/callback?code=abc&state=xyz")
            #expect(head.path == "/callback")
            #expect(head.headers["host"] == "127.0.0.1:5000")
            #expect(head.headers["accept"] == "*/*")
        }

        @Test func waitsForTheBlankLine() {
            #expect(parse("GET /callback HTTP/1.1\r\nHost: 127.0.0.1:5000\r\n") == .incomplete)
            #expect(parse("") == .incomplete)
        }

        @Test func ignoresBytesAfterTheHead() {
            let outcome = parse("GET / HTTP/1.0\r\nHost: a:1\r\n\r\nGET /second HTTP/1.1\r\n")
            guard case .complete(let head) = outcome else {
                Issue.record("expected a complete head")
                return
            }
            #expect(head.target == "/")
        }

        @Test(
            arguments: [
                "GET /callback\r\nHost: a:1\r\n\r\n",
                "GET /callback HTTP/2\r\nHost: a:1\r\n\r\n",
                "GET  /callback HTTP/1.1\r\nHost: a:1\r\n\r\n",
                "GET callback HTTP/1.1\r\nHost: a:1\r\n\r\n",
                "GET http://example.com/ HTTP/1.1\r\nHost: a:1\r\n\r\n",
                "GET /callback#fragment HTTP/1.1\r\nHost: a:1\r\n\r\n",
                "G@T /callback HTTP/1.1\r\nHost: a:1\r\n\r\n",
                "GET /callback HTTP/1.1\r\nHost a:1\r\n\r\n",
                "GET /callback HTTP/1.1\r\n Host: a:1\r\n\r\n",
                "GET /callback HTTP/1.1\r\nHost: a:1\r\nHost: b:2\r\n\r\n",
                "GET /callback HTTP/1.1\r\nBad Name: x\r\n\r\n",
                "GET /callback HTTP/1.1\nHost: a:1\n\n\r\n\r\n",
                "GET /callback HTTP/1.1\r\nHost: a:1\u{0}\r\n\r\n",
                "GET /caf\u{e9} HTTP/1.1\r\nHost: a:1\r\n\r\n",
            ]
        )
        func rejectsMalformedRequests(_ text: String) {
            #expect(parse(text) == .malformed)
        }

        @Test func rejectsHeadsOverTheLimit() {
            let padding = String(repeating: "a", count: LoopbackRequestHead.maximumSize)
            #expect(parse("GET /callback HTTP/1.1\r\nHost: a:1\r\nX-Padding: \(padding)\r\n\r\n") == .tooLarge)
            // No terminator yet and already at the limit: stop reading.
            #expect(parse("GET /callback?\(padding)") == .tooLarge)
        }

        @Test func acceptsHeadsJustUnderTheLimit() {
            let prefix = "GET /callback HTTP/1.1\r\nHost: a:1\r\nX-Padding: "
            let padding = String(repeating: "a", count: LoopbackRequestHead.maximumSize - prefix.utf8.count - 4)
            guard case .complete = parse(prefix + padding + "\r\n\r\n") else {
                Issue.record("a head of exactly the limit should be accepted")
                return
            }
        }

        @Test func routesOnlyTheLoopbackHostOnThisPort() {
            func route(method: String = "GET", target: String = "/callback?code=1&state=s", host: String?)
                -> LoopbackRoute
            {
                LoopbackRoute.route(
                    LoopbackRequestHead(method: method, target: target, headers: host.map { ["host": $0] } ?? [:]),
                    path: "/callback",
                    port: 5000
                )
            }
            #expect(route(host: "127.0.0.1:5000") == .callback(target: "/callback?code=1&state=s"))
            #expect(route(host: "LocalHost:5000") == .callback(target: "/callback?code=1&state=s"))
            #expect(route(host: "127.0.0.1:5001") == .reject(status: 400))
            #expect(route(host: "127.0.0.1") == .reject(status: 400))
            #expect(route(host: "attacker.example:5000") == .reject(status: 400))
            #expect(route(host: nil) == .reject(status: 400))
            #expect(route(method: "POST", host: "127.0.0.1:5000") == .reject(status: 405))
            #expect(route(target: "/other", host: "127.0.0.1:5000") == .reject(status: 404))
            #expect(route(target: "/callback/", host: "127.0.0.1:5000") == .reject(status: 404))
        }

        @Test(arguments: [
            "/callback", "/callback?code=1", "/callback?state=s", "/callback?other=1&state=s",
        ])
        func refusesRequestsThatAreNotAuthorizationResponses(target: String) {
            let head = LoopbackRequestHead(method: "GET", target: target, headers: ["host": "127.0.0.1:5000"])
            #expect(LoopbackRoute.route(head, path: "/callback", port: 5000) == .reject(status: 400))
        }

        @Test func acceptsAnErrorResponse() {
            let head = LoopbackRequestHead(
                method: "GET", target: "/callback?error=access_denied&state=s", headers: ["host": "127.0.0.1:5000"])
            #expect(LoopbackRoute.route(head, path: "/callback", port: 5000) == .callback(target: head.target))
        }

        @Test(arguments: [
            ("sec-fetch-mode", "no-cors", 400), ("sec-fetch-mode", "cors", 400), ("sec-fetch-mode", "navigate", 200),
            ("sec-fetch-dest", "image", 400), ("sec-fetch-dest", "iframe", 400), ("sec-fetch-dest", "document", 200),
        ])
        func refusesBackgroundRequests(header: String, value: String, status: Int) {
            let head = LoopbackRequestHead(
                method: "GET", target: "/callback?code=1&state=s", headers: ["host": "127.0.0.1:5000", header: value])
            let route = LoopbackRoute.route(head, path: "/callback", port: 5000)
            #expect(route == (status == 200 ? .callback(target: head.target) : .reject(status: status)))
        }
    }
#endif
