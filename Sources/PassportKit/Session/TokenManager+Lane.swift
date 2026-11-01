import Foundation
import Logging

// Operations that send the refresh token. They are the only code that reads `current.refreshToken` to send it,
// and they only run inside a lane turn (ADR 0005).
extension TokenManager {
    /// Exchanges the refresh token for tokens of another audience or resource (RFC 8693 §2.1).
    ///
    /// The subject is the current refresh token. The issued token (for the default `requestedTokenType`, a
    /// refresh token bound to `audiences`) is in `accessToken` of the returned response, whatever its type; the
    /// manager does not cache or judge it. A `refresh_token` in the server's response is the session's rotated
    /// subject: the manager saves it before this returns (persist before publish) and returns the response with
    /// ``TokenResponse/refreshToken`` set to `nil`, because that token belongs to the session alone. Using it
    /// elsewhere would present it twice and could make the server revoke the grant (RFC 9700 §4.14.2).
    ///
    /// Runs in the refresh token lane, so it never overlaps a refresh. `invalid_grant` ends the session (RFC
    /// 6749 §5.2).
    ///
    /// - Important: Cancelling the caller stops it waiting, nothing else: a request that was sent finishes and
    ///   its rotated subject is saved, but the issued token is not returned to anyone. It stays valid at the
    ///   server until it expires. A caller that must not lose the issued token does not cancel the call.
    ///
    /// - Important: The issued token belongs to the caller, not to the session, so a response the server sent
    ///   is returned even if the session ended or was replaced while the request was in flight (ADR 0015). Its
    ///   rotated subject is then not stored: it goes to the ended session's revocation, if it has one, and the
    ///   current session is not touched. A caller that must not use a token of an ended session checks its own
    ///   state when this returns and discards the token, revoking it as the client it was issued to (RFC 7009
    ///   §2.1); this manager cannot, because the token's audience need not be a client of its configuration.
    ///   A call whose session ended before its request was sent throws
    ///   ``PassportError/Code-swift.struct/notAuthenticated``, and a failure that arrives after the session
    ///   ended is reported the same way, so it never ends a newer session.
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
                let response = try await spendRefreshToken(
                    turn: turn, session: session, adoptsIDToken: false, returnsAnsweredResponse: true
                ) {
                    try await self.client.exchange(
                        TokenExchangeRequest(
                            subjectToken: $0, subjectTokenType: .refreshToken, requestedTokenType: requestedTokenType,
                            audiences: audiences, resources: resources, scope: scope))
                }
                // The rotated subject stays with the session (persisted above, or handed to its revocation).
                var issued = response
                issued.refreshToken = nil
                completion.complete(.success(issued))
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
    /// `invalid_grant` therefore never ends a newer session. With `returnsAnsweredResponse`, a response that
    /// arrived after the session changed is returned instead, without being persisted (ADR 0015).
    func spendRefreshToken(
        turn: RefreshLane.Turn,
        session: Int,
        adoptsIDToken: Bool,
        adoptsScope: Bool = false,
        returnsAnsweredResponse: Bool = false,
        send: (Secret) async throws -> TokenResponse
    ) async throws -> TokenResponse {
        logger.trace("Waiting for a refresh lane turn")
        await turn.start()
        defer {
            turn.finish()
            logger.trace("Refresh lane turn finished")
        }
        guard session == generation else {
            logger.trace("Skipped a lane turn of a superseded session")
            throw SessionSuperseded()
        }
        guard let refreshToken = current?.refreshToken else {
            // A grant that issued no refresh token cannot be renewed: its session ends with its access token.
            await endSession(reason: .expiredWithoutRefreshToken)
            throw Self.expiredWithoutRefreshToken
        }
        let response: TokenResponse
        do {
            response = try await send(refreshToken)
        } catch {
            guard session == generation else {
                logger.trace("Discarded a failure of a superseded session")
                throw SessionSuperseded()
            }
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
            if returnsAnsweredResponse {
                logger.trace("Returned the result of a superseded session to its caller")
                return response
            }
            logger.trace("Discarded the result of a superseded session")
            throw SessionSuperseded()
        }
        await persistRotation(from: response, adoptsIDToken: adoptsIDToken, adoptsScope: adoptsScope)
        guard session == generation || returnsAnsweredResponse else { throw SessionSuperseded() }
        return response
    }

    /// Stores the refresh token, and with `adoptsScope` the scope, carried by `response`: in memory first, so that `current` is always the newest
    /// token the manager knows, then in the store. A failing store is reported, not thrown: the session continues
    /// from memory.
    private func persistRotation(from response: TokenResponse, adoptsIDToken: Bool, adoptsScope: Bool) async {
        guard var credential = current, response.refreshToken != nil || (adoptsScope && response.scope != nil)
        else { return }
        if let rotated = response.refreshToken {
            credential.refreshToken = rotated
            logger.info("Refresh token rotated")
        }
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
        logger.info("Session ended", metadata: [LogKey.reason: "\(reason.logValue)"])
        await deleteStoredCredential()
    }

    /// Starts revoking the refresh token of the ended session `session`, which is `refreshToken` as of now, in
    /// its own lane turn, and returns what will become of it.
    ///
    /// The turn is reserved before this returns; the token is read when the turn starts. The request is limited
    /// to `OAuthClient.revocationTimeLimit` on the client's clock so a hung server cannot hold the lane.
    func startRevocation(of refreshToken: Secret, session: Int, lane: RefreshLane) -> Completion<
        RevocationOutcome
    >? {
        guard client.configuration.endpoints.revocation != nil else { return nil }
        revocableTokens[session] = refreshToken
        // The lane of the ended session: behind its in-flight requests, and not holding up the next session.
        let turn = lane.reserve()
        let completion = Completion<RevocationOutcome>()
        Task {
            await turn.start()
            defer { turn.finish() }
            let refreshToken = revocableTokens.removeValue(forKey: session) ?? refreshToken
            // The task is never cancelled, so the outcome is never `cancelled`.
            let outcome = await client.revokeBestEffort(refreshToken, typeHint: .refreshToken)
            completion.complete(.success(outcome))
        }
        return completion
    }
}
