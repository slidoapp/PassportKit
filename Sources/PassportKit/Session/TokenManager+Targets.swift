import Foundation

// Access tokens per target: cache lookup, coalescing, and the two ways of issuing a token.
extension TokenManager {
    /// Returns a token for `target`: the cached one while it has at least `minimumTokenLifetime` left,
    /// otherwise a new one.
    ///
    /// Concurrent callers for the same target share one operation, and different targets never receive each
    /// other's tokens. A refresh grant runs in the refresh token lane; an exchange first obtains the default
    /// token the same way, so a derived token never outlives its subject.
    ///
    /// Cancelling the caller stops waiting only; the operation finishes and its results are persisted.
    ///
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/notAuthenticated`` when there is
    /// no session (call ``load()`` or ``signIn(with:requestedScope:)`` first) and
    /// ``PassportError/Code-swift.struct/tokenRejected`` with recovery
    /// ``PassportError/Recovery-swift.enum/resourceDenied`` when the acceptance policy rejects the token; the
    /// session stays signed in. An error whose recovery is ``PassportError/Recovery-swift.enum/reauthenticate``
    /// from the refresh token has ended the session.
    public func accessToken(for target: TokenTarget = .default) async throws -> AccessToken {
        try Task.checkCancellation()
        do {
            return try await resolveToken(for: target)
        } catch is SessionSuperseded {
            // The session this call joined ended or was replaced. If a session exists now (a sign-in replaced
            // it), the caller's question is still open and gets one answer from it; a second supersession
            // means the session changed again, and the caller is told.
            guard current != nil else { throw Self.superseded }
            do {
                return try await resolveToken(for: target)
            } catch is SessionSuperseded {
                throw Self.superseded
            }
        }
    }

    /// The body of ``accessToken(for:)``. Everything up to the final `await` is synchronous, so a second
    /// caller always finds the flight registered by the first.
    func resolveToken(for target: TokenTarget) async throws -> AccessToken {
        guard current != nil else { throw Self.signedOut }
        if target.derivation == .refreshGrant, !target.audiences.isEmpty {
            throw PassportError(
                .invalidConfiguration, detail: "A refresh grant target cannot name audiences.")
        }
        let minimumLifetime = client.configuration.minimumTokenLifetime.seconds
        if let token = cache.usableToken(for: target, now: client.wallClock.now(), minimumLifetime: minimumLifetime) {
            return token
        }
        // A token that was just rejected is not asked for again: every attempt would rotate the refresh token.
        let now = client.wallClock.now()
        if let rejection = cache.rejection(for: target, now: now) { throw rejection }
        let flight = flights[target] ?? startFlight(for: target)
        return try await flight.completion.wait()
    }

    /// Registers the operation that will produce the token of `target`, so that later callers wait for it.
    func registerFlight(for target: TokenTarget) -> Flight {
        lastFlightIdentifier += 1
        let flight = Flight(identifier: lastFlightIdentifier, completion: Completion())
        flights[target] = flight
        return flight
    }

    /// Ends `flight`: forgets it and wakes its waiters. No suspension in between, so a caller never sees a gap
    /// where neither the cache nor a flight holds the token.
    func finish(_ flight: Flight, of target: TokenTarget, with result: Result<AccessToken, any Error>) {
        if flights[target]?.identifier == flight.identifier { flights[target] = nil }
        flight.completion.complete(result)
    }

    private func startFlight(for target: TokenTarget) -> Flight {
        let flight = registerFlight(for: target)
        let session = generation
        // The lane turn is reserved here, synchronously, so turns follow the order of calls.
        let turn = target.derivation == .refreshGrant ? lane.reserve() : nil
        Task {
            let result: Result<AccessToken, any Error>
            do {
                let token =
                    if let turn {
                        try await issueByRefreshGrant(target, turn: turn, session: session)
                    } else {
                        try await issueByExchange(target, session: session)
                    }
                guard session == generation else { throw SessionSuperseded() }
                publish(token)
                eventHub.emit(.refreshed(target: target))
                result = .success(token)
            } catch {
                result = .failure(error)
            }
            finish(flight, of: target, with: result)
        }
        return flight
    }

    private func issueByRefreshGrant(_ target: TokenTarget, turn: RefreshLane.Turn, session: Int) async throws
        -> AccessToken
    {
        let response = try await spendRefreshToken(turn: turn, session: session, adoptsIDToken: true) {
            try await self.client.refresh($0, scope: target.scope, resources: target.resources)
        }
        let token = makeToken(from: response, target: target, requestedScope: target.scope)
        try await accept(token, response: response, session: session)
        return token
    }

    /// RFC 8693 exchange of the default access token. Does not touch the refresh token, so it is not in the
    /// lane; a `refresh_token` in the response is not the root grant and is ignored.
    private func issueByExchange(_ target: TokenTarget, session: Int) async throws -> AccessToken {
        // The default token has at least `minimumTokenLifetime` left, because the same rules produced it.
        let subject = try await resolveToken(for: .default)
        guard session == generation else { throw SessionSuperseded() }
        let response: TokenResponse
        do {
            response = try await client.exchange(
                TokenExchangeRequest(
                    subjectToken: subject.value, subjectTokenType: .accessToken, requestedTokenType: .accessToken,
                    audiences: target.audiences, resources: target.resources, scope: target.scope))
        } catch {
            guard session == generation else { throw SessionSuperseded() }
            // The server no longer accepts the subject: do not offer it again.
            if (error as? PassportError)?.code == .invalidGrant {
                cache.remove(target: .default, generation: subject.generation)
            }
            throw error
        }
        guard session == generation else { throw SessionSuperseded() }
        if let issued = response.issuedTokenType, issued != .accessToken {
            throw PassportError(.invalidResponse, detail: "The exchange did not issue an access token.")
        }
        let token = makeToken(from: response, target: target, requestedScope: target.scope, notAfter: subject.expiresAt)
        try await accept(token, response: response, session: session)
        return token
    }

    /// Builds the token of `response`. Its expiry is `expires_in`, else the configured default lifetime,
    /// else unknown, and never later than `notAfter` (the subject's expiry, for derived tokens).
    func makeToken(
        from response: TokenResponse,
        target: TokenTarget,
        requestedScope: ScopeSet?,
        notAfter: Date? = nil
    ) -> AccessToken {
        let lifetime = response.expiresIn ?? client.configuration.defaultTokenLifetime
        var expiresAt = lifetime.map { client.wallClock.now().addingTimeInterval($0.seconds) }
        if let limit = notAfter, let own = expiresAt, limit < own { expiresAt = limit }
        return AccessToken(
            value: response.accessToken,
            tokenType: response.tokenType,
            expiresAt: expiresAt,
            grantedScope: response.grantedScope(requested: requestedScope),
            target: target,
            generation: cache.nextGeneration(),
            additionalFields: response.additionalFields
        )
    }

    /// Runs the acceptance policy, limited to `acceptancePolicyTimeLimit`: a policy that does not answer in time
    /// rejects the token, so it cannot hold the refresh token lane forever. A rejection is remembered for
    /// `rejectedTokenCacheDuration`, reported and thrown, unless the session changed meanwhile.
    func accept(_ token: AccessToken, response: TokenResponse, session: Int) async throws {
        let policy = acceptancePolicy
        // The default policy cannot hang, so it needs no timer.
        let verdict =
            policy is AcceptAnyToken
            ? .accept
            : (try? await withTimeLimit(acceptancePolicyTimeLimit, clock: client.clock) {
                await policy.evaluate(TokenAcceptanceContext(token: token, response: response))
            }) ?? .reject(reason: "The acceptance policy did not answer in time.")
        guard case .reject(let reason) = verdict, session == generation else { return }
        let error = PassportError(.tokenRejected, recovery: .resourceDenied, detail: reason)
        cache.reject(
            target: token.target, error: error,
            until: client.wallClock.now().addingTimeInterval(rejectedTokenCacheDuration.seconds))
        eventHub.emit(.tokenRejected(target: token.target, grantedScope: token.grantedScope))
        throw error
    }

    /// Caches `token` when its expiry is known. A token without one is used once and then issued again.
    func publish(_ token: AccessToken) {
        if token.expiresAt != nil { cache.store(token) }
    }
}
