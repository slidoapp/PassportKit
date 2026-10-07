import Foundation

// Operations that send the refresh token. They are the only code that reads `current.refreshToken` to send it,
// and they only run inside a lane turn (ADR 0005).
extension TokenManager {
    /// Exchanges the refresh token for tokens of another audience or resource (RFC 8693 §2.1).
    ///
    /// The subject is the current refresh token. The response is returned as it came: the issued token (for
    /// the default `requestedTokenType`, a refresh token bound to `audience`) is in `accessToken`, whatever its
    /// type. The manager does not cache or judge it. A `refresh_token` in the response is the rotated subject
    /// and is saved before this returns (persist before publish).
    ///
    /// Runs in the refresh token lane, so it never overlaps a refresh. Cancelling the caller stops waiting only:
    /// a request that was sent finishes and its rotated refresh token is saved. `invalid_grant` ends the
    /// session (RFC 6749 §5.2).
    public func exchangeRefreshToken(
        audience: String?,
        resources: [URL] = [],
        scope: ScopeSet? = nil,
        requestedTokenType: TokenTypeIdentifier = .refreshToken
    ) async throws -> TokenResponse {
        try Task.checkCancellation()
        guard current?.refreshToken != nil else { throw Self.signedOut }
        let session = generation
        let ticket = lane.reserve()
        let completion = Completion<TokenResponse>()
        Task {
            do {
                let response = try await spendRefreshToken(ticket: ticket, session: session, adoptsIDToken: false) {
                    try await self.client.exchange(
                        TokenExchangeRequest(
                            subjectToken: $0, subjectTokenType: .refreshToken, requestedTokenType: requestedTokenType,
                            audiences: audience.map { [$0] } ?? [], resources: resources, scope: scope))
                }
                completion.complete(.success(response))
            } catch {
                completion.complete(.failure(error))
            }
        }
        return try await completion.wait()
    }

    /// One lane turn: sends the refresh token with `send` and persists the rotated one before the turn ends.
    ///
    /// The token is read when the turn starts, so it is whatever the previous turn persisted. Throws
    /// ``superseded`` instead of sending, or instead of returning, when the session changed meanwhile; a stale
    /// `invalid_grant` therefore never ends a newer session.
    func spendRefreshToken(
        ticket: Completion<Void>,
        session: Int,
        adoptsIDToken: Bool,
        send: (Secret) async throws -> TokenResponse
    ) async throws -> TokenResponse {
        await ticket.turn()
        defer { lane.leave() }
        guard session == generation else { throw Self.superseded }
        guard let refreshToken = current?.refreshToken else { throw Self.signedOut }
        let response: TokenResponse
        do {
            response = try await send(refreshToken)
        } catch {
            guard session == generation else { throw Self.superseded }
            // Only a rejected refresh token ends the session; resource-level failures never do.
            if (error as? PassportError)?.recovery == .reauthenticate {
                await endSession(reason: .refreshTokenRejected)
            }
            throw error
        }
        guard session == generation else {
            handOverRotation(of: response, session: session)
            throw Self.superseded
        }
        await persistRotation(from: response, adoptsIDToken: adoptsIDToken)
        guard session == generation else { throw Self.superseded }
        return response
    }

    /// Stores the refresh token carried by `response`: in memory first, so that `current` is always the newest
    /// token the manager knows, then in the store. A failing store is reported, not thrown: the session continues
    /// from memory.
    private func persistRotation(from response: TokenResponse, adoptsIDToken: Bool) async {
        guard var credential = current, let rotated = response.refreshToken else { return }
        credential.refreshToken = rotated
        if adoptsIDToken, let idToken = response.idToken { credential.idToken = idToken }
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
    func startRevocation(of refreshToken: Secret, session: Int) -> Completion<SignOutResult.Revocation>? {
        guard client.configuration.endpoints.revocation != nil else { return nil }
        revocableTokens[session] = refreshToken
        let ticket = lane.reserve()
        let completion = Completion<SignOutResult.Revocation>()
        Task {
            await ticket.turn()
            defer { lane.leave() }
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
