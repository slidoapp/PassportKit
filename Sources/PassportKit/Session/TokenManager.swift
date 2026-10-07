import Foundation

/// The session: one signed-in root grant and every access token derived from it (specification §9).
///
/// ## Concurrency
///
/// The manager is an actor, and every operation that takes time (a request to the authorization server, a
/// store call, the acceptance policy) suspends it, so other calls run in between. Three rules keep that safe:
///
/// - Bookkeeping that other callers must see (registering an in-flight operation, reserving a lane turn,
///   bumping the generation) happens synchronously, before the first `await` of the call.
/// - In-flight work runs in an unstructured task the manager owns and never cancels. Callers only wait on a
///   ``Completion``; cancelling a caller stops that caller waiting, nothing else.
/// - Every suspension is followed by a generation check before results are written or published, so work
///   started under a session that has since ended or been replaced is discarded.
public actor TokenManager {
    /// The longest `signOut(revoke:)` waits for the revocation request, and the request itself runs.
    static let revocationTimeLimit = Duration.seconds(5)

    /// Thrown inside the manager when work finds that its session ended or was replaced. The public methods
    /// never let it escape: they resolve again on the session that exists now, or report ``superseded``.
    struct SessionSuperseded: Error {}

    /// An operation producing the token of one target, shared by every caller of that target.
    struct Flight: Sendable {
        let identifier: Int
        let completion: Completion<AccessToken>
    }

    let client: OAuthClient
    let store: any CredentialStore
    let account: CredentialAccount
    let acceptancePolicy: any TokenAcceptancePolicy
    let eventHub = EventHub()

    /// The root credential; the single source of truth for the refresh token.
    var current: Credential?
    /// Incremented whenever the session is replaced or ends. Work started under an older value is stale.
    var generation = 0
    var cache = TokenCache()
    var flights: [TokenTarget: Flight] = [:]
    var lane = RefreshLane()
    var lastFlightIdentifier = 0
    /// The newest change to the store. The next change waits for it (see ``changeStore(_:)``).
    var lastStoreChange: Task<Bool, Never>?
    /// For each session that ended with a sign-out that revokes: the newest refresh token known to belong to
    /// it. The revocation reads it when its lane turn starts, so it sends the token that is live then, not the
    /// one that was live when the user signed out (see ``spendRefreshToken(turn:session:adoptsIDToken:send:)``).
    var revocableTokens: [Int: Secret] = [:]

    /// Creates a manager with no session. Call ``load()`` to restore one from `store`.
    ///
    /// `account` names where the credential is stored. `acceptancePolicy` judges every issued access token
    /// (ADR 0004).
    public init(
        client: OAuthClient,
        store: any CredentialStore,
        account: CredentialAccount,
        acceptancePolicy: any TokenAcceptancePolicy = AcceptAnyToken()
    ) {
        self.client = client
        self.store = store
        self.account = account
        self.acceptancePolicy = acceptancePolicy
    }

    deinit {
        eventHub.finish()
    }

    /// Session events. Each access returns a new stream that sees every event from then on; earlier events
    /// are not replayed, so subscribe before ``load()`` or ``signIn(with:requestedScope:)``.
    ///
    /// Streams end when the manager is released.
    public nonisolated var events: AsyncStream<SessionEvent> {
        eventHub.subscribe()
    }

    /// The root credential, or `nil` when signed out.
    public var credential: Credential? { current }

    /// Restores the session from the store.
    ///
    /// A stored credential for another client or issuer is ignored and left in place (specification §9). Does
    /// nothing when a session is already active. Throws ``PassportError`` with code
    /// ``PassportError/Code-swift.struct/storageFailure`` when the store fails.
    public func load() async throws -> Credential? {
        let session = generation
        let stored: Credential?
        do {
            stored = try await store.load(account)
        } catch {
            throw Self.storageError(error)
        }
        // A sign-in or sign-out that ran while the store was reading wins.
        guard session == generation, current == nil else { return current }
        guard let stored, stored.clientID == client.configuration.authentication.clientID,
            stored.issuer == client.configuration.issuer
        else { return nil }
        current = stored
        eventHub.emit(.signedIn)
        return stored
    }

    /// Adopts the result of a grant (authorization code, device authorization, ...) as the session.
    ///
    /// The previous session, if any, is replaced without revoking it: results of its in-flight operations are
    /// discarded. The credential is saved before this returns; if saving fails the session continues in memory
    /// and ``SessionEvent/storageFailed`` is emitted. The access token of `response` becomes the cached
    /// default token when its lifetime is known. `requestedScope` is the scope of the grant request, used when
    /// the response omits `scope` (RFC 6749 §5.1).
    ///
    /// Throws ``PassportError`` with code ``PassportError/Code-swift.struct/tokenRejected`` when the
    /// acceptance policy rejects the access token. The session is still established.
    public func signIn(with response: TokenResponse, requestedScope: ScopeSet?) async throws {
        startNewSession()
        let session = generation
        let credential = Credential(
            clientID: client.configuration.authentication.clientID,
            issuer: client.configuration.issuer,
            refreshToken: response.refreshToken,
            idToken: response.idToken,
            grantedScope: response.grantedScope(requested: requestedScope),
            updatedAt: client.wallClock.now()
        )
        let token = makeToken(from: response, target: .default, requestedScope: requestedScope)
        current = credential
        eventHub.emit(.signedIn)
        // The token is not cached until it was saved with its credential and judged, which takes a while. Until
        // then this flight stands in for it: a caller asking for the default token in that time waits here
        // instead of refreshing, which would spend the grant's first refresh token and then be overwritten by
        // the older token published below.
        let flight = registerFlight(for: .default)
        let result: Result<AccessToken, any Error>
        do {
            await save(credential)
            guard session == generation else { throw SessionSuperseded() }
            try await accept(token, response: response, session: session)
            guard session == generation else { throw SessionSuperseded() }
            publish(token)
            result = .success(token)
        } catch {
            result = .failure(error)
        }
        finish(flight, of: .default, with: result)
        if case .failure(let error) = result, !(error is SessionSuperseded) { throw error }
    }

    /// Marks an access token as unusable, typically after a 401 (RFC 6750 §3.1).
    ///
    /// The cached token of the target is dropped only if it is still `token`, so many concurrent 401s for
    /// the same token cause one refresh, and a late report cannot discard a newer token.
    public func invalidate(_ token: AccessToken) {
        cache.remove(target: token.target, generation: token.generation)
    }

    /// Ends the session: clears local state, then revokes the refresh token at the server (RFC 7009).
    ///
    /// Local state is cleared first and always, whatever happens to the revocation, which is best effort and
    /// limited to five seconds. In-flight operations of the ended session are discarded.
    public func signOut(revoke: Bool = true) async -> SignOutResult {
        let endedSession = generation
        let endedLane = lane
        let snapshot = current?.refreshToken
        startNewSession()
        current = nil
        // Reported before the first suspension, so a slow store cannot order it after the events of a sign-in
        // that follows.
        eventHub.emit(.signedOut(reason: .userInitiated))
        // Reserved now, before any suspension, so the revocation queues behind operations that are
        // already sending the old refresh token.
        let revocation =
            revoke ? snapshot.flatMap { startRevocation(of: $0, session: endedSession, lane: endedLane) } : nil
        let isDeleted = await deleteStoredCredential()
        guard let revocation else { return SignOutResult(isStoredCredentialDeleted: isDeleted, revocation: .skipped) }
        let outcome = try? await withTimeLimit(Self.revocationTimeLimit, clock: client.clock) {
            try await revocation.wait()
        }
        return SignOutResult(isStoredCredentialDeleted: isDeleted, revocation: outcome ?? .timedOut)
    }

    /// Replaces the session: stale work is discarded, cached tokens and in-flight operations are forgotten.
    func startNewSession() {
        generation += 1
        cache.removeAll()
        flights.removeAll()
        lane = RefreshLane()
    }

    /// Applies `change` to the store after every earlier change has finished, and reports whether it succeeded.
    ///
    /// Saves and deletes are decided in the actor, in order, but a store may take a long time for each and
    /// finish them in any order if they overlap. Running them one after the other, in the order they were
    /// requested, means the store always ends in the state the manager last decided: a sign-out is never undone
    /// by a save that was still on its way. The change is registered before this returns and runs in a task of
    /// its own, so cancelling the caller neither skips it nor interrupts it. A failure is reported as
    /// ``SessionEvent/storageFailed``.
    func changeStore(_ change: @escaping @Sendable () async throws -> Void) -> Task<Bool, Never> {
        let previous = lastStoreChange
        let task = Task {
            _ = await previous?.value
            do {
                try await change()
                return true
            } catch {
                eventHub.emit(.storageFailed)
                return false
            }
        }
        lastStoreChange = task
        return task
    }

    @discardableResult
    func save(_ credential: Credential) async -> Bool {
        let store = self.store
        let account = self.account
        return await changeStore { try await store.save(credential, for: account) }.value
    }

    @discardableResult
    func deleteStoredCredential() async -> Bool {
        let store = self.store
        let account = self.account
        return await changeStore { try await store.delete(account) }.value
    }

    static func storageError(_ error: any Error) -> PassportError {
        error as? PassportError
            ?? PassportError(.storageFailure, errorDescription: "The credential store failed.", underlying: error)
    }

    static var superseded: PassportError {
        PassportError(
            .notAuthenticated,
            recovery: .reauthenticate,
            errorDescription: "The session ended or was replaced while the request was in flight."
        )
    }

    static var expiredWithoutRefreshToken: PassportError {
        PassportError(
            .notAuthenticated, recovery: .reauthenticate,
            errorDescription: "The access token expired and the grant has no refresh token.")
    }

    static var signedOut: PassportError {
        PassportError(.notAuthenticated, recovery: .reauthenticate, errorDescription: "There is no signed-in session.")
    }
}
