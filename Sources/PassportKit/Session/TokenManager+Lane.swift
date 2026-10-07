import Foundation

// Operations that send the refresh token. They are the only code that reads `current.refreshToken` to send it,
// and they only run inside a lane turn (ADR 0005).
extension TokenManager {
    /// Exchanges the refresh token for tokens of another audience or resource (RFC 8693 §2.1).
    ///
    /// The subject is the current refresh token. The response is returned as it came: the issued token (for
    /// the default `requestedTokenType`, a refresh token bound to `audiences`) is in `accessToken`, whatever its
    /// type. The manager does not cache or judge it. A `refresh_token` in the response is the rotated subject
    /// and is saved before this returns (persist before publish).
    ///
    /// Runs in the refresh token lane, so it never overlaps a refresh. Cancelling the caller stops waiting only:
    /// a request that was sent finishes and its rotated refresh token is saved. `invalid_grant` ends the
    /// session (RFC 6749 §5.2).
    public func exchangeRefreshToken(
        audiences: [String] = [],
        resources: [URL] = [],
        scope: ScopeSet? = nil,
        requestedTokenType: TokenTypeIdentifier = .refreshToken
    ) async throws -> TokenResponse {
        try Task.checkCancellation()
        guard current?.refreshToken != nil else { throw Self.signedOut }
        let session = generation
        let turn = lane.reserve()
        let completion = Completion<TokenResponse>()
        Task {
            do {
                let response = try await spendRefreshToken(turn: turn, session: session, adoptsIDToken: false) {
                    try await self.client.exchange(
                        TokenExchangeRequest(
                            subjectToken: $0, subjectTokenType: .refreshToken, requestedTokenType: requestedTokenType,
                            audiences: audiences, resources: resources, scope: scope))
                }
                completion.complete(.success(response))
            } catch {
                completion.complete(.failure(error))
            }
        }
        do {
            return try await completion.wait()
        } catch is SessionSuperseded {
            throw Self.superseded
        }
    }

    /// One lane turn: sends the refresh token with `send` and persists the rotated one before the turn ends.
    ///
    /// The token is read when the turn starts, so it is whatever the previous turn persisted. Throws
    /// ``superseded`` instead of sending, or instead of returning, when the session changed meanwhile; a stale
    /// `invalid_grant` therefore never ends a newer session.
    func spendRefreshToken(
        turn: RefreshLane.Turn,
        session: Int,
        adoptsIDToken: Bool,
        adoptsScope: Bool = false,
        send: (Secret) async throws -> TokenResponse
    ) async throws -> TokenResponse {
        await turn.start()
        defer { turn.finish() }
        guard session == generation else { throw SessionSuperseded() }
        guard let refreshToken = current?.refreshToken else {
            // A grant that issued no refresh token cannot be renewed: its session ends with its access token.
            await endSession(reason: .expiredWithoutRefreshToken)
            throw Self.expiredWithoutRefreshToken
        }
        let response: TokenResponse
        do {
            response = try await send(refreshToken)
        } catch {
            guard session == generation else { throw SessionSuperseded() }
            // Only a rejected refresh token ends the session; resource-level failures never do. A refresh
            // narrowed to resources or a scope that fails with `invalid_grant` counts: RFC 6749 §5.2 defines it
            // as a problem with the grant, while scope and resource problems are `invalid_scope` and
            // `invalid_target`, which have other recoveries.
            if (error as? PassportError)?.recovery == .reauthenticate {
                await endSession(reason: .refreshTokenRejected)
            }
            throw error
        }
        guard session == generation else {
            handOverRotation(of: response, session: session)
            throw SessionSuperseded()
        }
        await persistRotation(from: response, adoptsIDToken: adoptsIDToken, adoptsScope: adoptsScope)
        guard session == generation else { throw SessionSuperseded() }
        return response
    }

    /// Stores the refresh token, and with `adoptsScope` the scope, carried by `response`: in memory first, so that `current` is always the newest
    /// token the manager knows, then in the store. A failing store is reported, not thrown: the session continues
    /// from memory.
    private func persistRotation(from response: TokenResponse, adoptsIDToken: Bool, adoptsScope: Bool) async {
        guard var credential = current, response.refreshToken != nil || (adoptsScope && response.scope != nil)
        else { return }
        if let rotated = response.refreshToken { credential.refreshToken = rotated }
        if adoptsIDToken, response.refreshToken != nil, let idToken = response.idToken { credential.idToken = idToken }
        if adoptsScope, let scope = response.scope { credential.grantedScope = scope }
        credential.updatedAt = client.wallClock.now()
        current = credential
        await save(credential)
    }

    /// A request that finished after its session ended still made the server rotate the refresh token. The result
    /// is discarded, but if the session was signed out with revocation, the revocation must target this newer
    /// token: revoking the one it replaced would leave the live one valid (RFC 7009 §2.1 only promises the
    /// token and, at the server's discretion, its grant).
    private func handOverRotation(of response: TokenResponse, session: Int) {
        guard revocableTokens[session] != nil, let rotated = response.refreshToken else { return }
        revocableTokens[session] = rotated
    }

    /// Ends the session because the server rejected the refresh token.
    private func endSession(reason: SignOutReason) async {
        startNewSession()
        current = nil
        eventHub.emit(.signedOut(reason: reason))
        await deleteStoredCredential()
    }

    /// Starts revoking the refresh token of the ended session `session`, which is `refreshToken` as of now, in
    /// its own lane turn, and returns what will become of it.
    ///
    /// The turn is reserved before this returns; the token is read when the turn starts. The request is limited to `revocationTimeLimit` on the
    /// client's clock so a hung server cannot hold the lane.
    func startRevocation(of refreshToken: Secret, session: Int, lane: RefreshLane) -> Completion<
        SignOutResult.Revocation
    >? {
        guard client.configuration.endpoints.revocation != nil else { return nil }
        revocableTokens[session] = refreshToken
        // The lane of the ended session: behind its in-flight requests, and not holding up the next session.
        let turn = lane.reserve()
        let completion = Completion<SignOutResult.Revocation>()
        Task {
            await turn.start()
            defer { turn.finish() }
            let client = self.client
            let refreshToken = revocableTokens.removeValue(forKey: session) ?? refreshToken
            let outcome: SignOutResult.Revocation
            do {
                let finished = try await withTimeLimit(Self.revocationTimeLimit, clock: client.clock) {
                    try await client.revoke(refreshToken, typeHint: .refreshToken)
                    return true
                }
                outcome = finished == nil ? .timedOut : .revoked
            } catch {
                outcome = .failed(error as? PassportError ?? PassportError(.transportFailure, underlying: error))
            }
            completion.complete(.success(outcome))
        }
        return completion
    }
}
