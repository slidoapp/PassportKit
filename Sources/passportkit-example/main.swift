// A small command-line client that shows how to use PassportKit against any standards-compliant
// authorization server: discovery, a sign-in flow, a session, and one refresh. Token values are never printed.
//
//   passportkit-example --issuer https://as.example.com --client-id app --scope "openid offline_access" \
//       --flow device
//
// Options: --flow device|code (default device), --prompt <value> for the code flow (some servers need
// `consent` to issue a refresh token), --no-browser to print the authorization URL instead of opening it.

import Foundation
import PassportKit

#if canImport(Network)
    import PassportKitApple
#endif

struct Arguments {
    var issuer: URL
    var clientID: String
    var scope: ScopeSet
    var flow: String
    var prompt: String?
    var opensBrowser: Bool

    static let usage = """
        usage: passportkit-example --issuer <url> --client-id <id> --scope "<scopes>" [--flow device|code]
                                   [--prompt <value>] [--no-browser]
        """

    init(_ arguments: [String]) throws {
        var values: [String: String] = [:]
        var flags: Set<String> = []
        var iterator = arguments.makeIterator()
        while let name = iterator.next() {
            switch name {
            case "--no-browser": flags.insert(name)
            case "--issuer", "--client-id", "--scope", "--flow", "--prompt":
                guard let value = iterator.next() else { throw ExampleError("Missing value for \(name).") }
                values[name] = value
            default: throw ExampleError("Unknown argument \(name).")
            }
        }
        guard let issuerText = values["--issuer"], let issuer = URL(string: issuerText),
            let clientID = values["--client-id"], let scope = values["--scope"]
        else { throw ExampleError("--issuer, --client-id and --scope are required.") }
        let flow = values["--flow"] ?? "device"
        guard flow == "device" || flow == "code" else { throw ExampleError("--flow must be device or code.") }
        self.issuer = issuer
        self.clientID = clientID
        self.scope = ScopeSet(parsing: scope)
        self.flow = flow
        self.prompt = values["--prompt"]
        self.opensBrowser = !flags.contains("--no-browser")
    }
}

struct ExampleError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

func signIn(arguments: Arguments, client: OAuthClient) async throws -> TokenResponse {
    switch arguments.flow {
    case "device":
        let authorization = try await client.startDeviceAuthorization(scope: arguments.scope)
        print("Open \(authorization.verificationURIComplete ?? authorization.verificationURI)")
        print("and enter the code \(authorization.userCode) if asked.")
        print("Waiting for approval (polling every \(authorization.interval))...")
        return try await client.completeDeviceAuthorization(authorization)
    default:
        #if canImport(Network)
            let listener = try await LoopbackRedirectListener.start()
            let request = AuthorizationRequest(
                redirectURI: listener.redirectURI, scope: arguments.scope, prompt: arguments.prompt)
            let opensBrowser = arguments.opensBrowser
            let agent = LoopbackUserAgent(listener: listener) { url in
                if opensBrowser {
                    try await LoopbackUserAgent.openInSystemBrowser(url)
                } else {
                    print("Open this URL in a browser: \(url)")
                }
            }
            return try await client.authorize(request, using: agent)
        #else
            throw ExampleError("The code flow needs the loopback listener, which is available on Apple platforms.")
        #endif
    }
}

func describe(_ response: TokenResponse) -> String {
    let scope = response.scope?.rawValue ?? "(not reported)"
    let lifetime = response.expiresIn.map { "\($0)" } ?? "(not reported)"
    return "scope: \(scope)\nexpires in: \(lifetime)\nrefresh token: \(response.refreshToken == nil ? "no" : "yes")"
}

func run() async throws {
    let arguments = try Arguments(Array(CommandLine.arguments.dropFirst()))

    // RFC 8414 discovery; the configuration follows what the server advertises (endpoints, RFC 9207).
    let metadata = try await Discovery.fetchMetadata(issuer: arguments.issuer)
    let configuration = try ClientConfiguration(
        metadata: metadata, authentication: .none(clientID: arguments.clientID))
    print("Discovered \(metadata.issuer)")
    let client = try OAuthClient(configuration: configuration)

    let response = try await signIn(arguments: arguments, client: client)
    print("Signed in.\n\(describe(response))")

    // The manager owns the refresh token and rotates it; a real app passes a persistent store.
    let account = CredentialAccount(service: "passportkit-example", account: arguments.clientID)
    let manager = TokenManager(client: client, store: InMemoryCredentialStore(), account: account)
    try await manager.signIn(with: response, requestedScope: arguments.scope)

    guard let before = await manager.credential?.refreshToken else {
        print("The server issued no refresh token, so there is nothing to refresh.")
        return
    }
    // A target with an explicit scope is a different token than the one from sign-in, so it is refreshed.
    let token = try await manager.accessToken(for: TokenTarget(scope: arguments.scope))
    let after = await manager.credential?.refreshToken
    let remaining = token.expiresAt.map { "\(Int($0.timeIntervalSince(client.wallClock.now())))s" } ?? "(not reported)"
    print("Refreshed once.\nscope: \(token.grantedScope?.rawValue ?? "(not reported)")\nexpires in: \(remaining)")
    print("refresh token rotated: \(after != before ? "yes" : "no")")
}

#if canImport(Darwin)
    setvbuf(stdout, nil, _IOLBF, 0)  // show the user code while the flow waits, even when piped
#endif
do {
    try await run()
} catch {
    FileHandle.standardError.write(Data("error: \(error)\n\(Arguments.usage)\n".utf8))
    exit(1)
}
