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
        return try await resolveToken(for: target)
    }

    /// The body of ``accessToken(for:)``. Everything up to the final `await` is synchronous, so a second
    /// caller always finds the flight registered by the first.
    func resolveToken(for target: TokenTarget) async throws -> AccessToken {
        guard current != nil else { throw Self.signedOut }
        if target.method == .refreshGrant, !target.audiences.isEmpty {
            throw PassportError(
                .invalidConfiguration, errorDescription: "A refresh grant target cannot name audiences.")
        }
        let minimumLifetime = client.configuration.minimumTokenLifetime.seconds
        if let token = cache.usableToken(for: target, now: client.wallClock.now(), minimumLifetime: minimumLifetime) {
            return token
        }
        let flight = flights[target] ?? startFlight(for: target)
        return try await flight.completion.wait()
    }

    private func startFlight(for target: TokenTarget) -> Flight {
        lastFlightIdentifier += 1
        let flight = Flight(identifier: lastFlightIdentifier, completion: Completion())
        flights[target] = flight
        let session = generation
        // The lane turn is reserved here, synchronously, so turns follow the order of calls.
        let ticket = target.method == .refreshGrant ? lane.reserve() : nil
        Task {
            let result: Result<AccessToken, any Error>
            do {
                let token =
                    if let ticket {
                        try await issueByRefreshGrant(target, ticket: ticket, session: session)
                    } else {
                        try await issueByExchange(target, session: session)
                    }
                // Publishing, ending the flight and waking the waiters happen with no suspension between them,
                // so a caller never sees a gap where neither the cache nor a flight holds the token.
                guard session == generation else { throw Self.superseded }
                publish(token)
                eventHub.emit(.refreshed(target: target))
                result = .success(token)
            } catch {
                result = .failure(error)
            }
            if flights[target]?.identifier == flight.identifier { flights[target] = nil }
            flight.completion.complete(result)
        }
        return flight
    }

    private func issueByRefreshGrant(_ target: TokenTarget, ticket: Completion<Void>, session: Int) async throws
        -> AccessToken
    {
        let response = try await spendRefreshToken(ticket: ticket, session: session, adoptsIDToken: true) {
            try await self.client.refresh(refreshToken: $0, scope: target.scope, resources: target.resources)
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
        guard session == generation else { throw Self.superseded }
        let response: TokenResponse
        do {
            response = try await client.exchange(
                TokenExchangeRequest(
                    subjectToken: subject.value, subjectTokenType: .accessToken, requestedTokenType: .accessToken,
                    audiences: target.audiences, resources: target.resources, scope: target.scope))
        } catch {
            guard session == generation else { throw Self.superseded }
            // The server no longer accepts the subject: do not offer it again.
            if (error as? PassportError)?.code == .invalidGrant {
                cache.remove(target: .default, generation: subject.generation)
            }
            throw error
        }
        guard session == generation else { throw Self.superseded }
        if let issued = response.issuedTokenType, issued != .accessToken {
            throw PassportError(.invalidResponse, errorDescription: "The exchange did not issue an access token.")
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

    /// Runs the acceptance policy. A rejection is reported and thrown unless the session changed meanwhile.
    func accept(_ token: AccessToken, response: TokenResponse, session: Int) async throws {
        guard case .reject(let reason) = await acceptancePolicy.evaluate(token, response: response),
            session == generation
        else { return }
        eventHub.emit(.tokenRejected(target: token.target, grantedScope: token.grantedScope))
        throw PassportError(.tokenRejected, recovery: .resourceDenied, errorDescription: reason)
    }

    /// Caches `token` when its expiry is known. A token without one is used once and then issued again.
    func publish(_ token: AccessToken) {
        if token.expiresAt != nil { cache.store(token) }
    }
}
