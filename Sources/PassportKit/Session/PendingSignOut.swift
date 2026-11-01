/// A sign-out whose local part is done and whose store delete and revocation (RFC 7009 §2) may still run.
///
/// Returned by ``TokenManager/beginSignOut(revoke:)``. By the time you hold one, the session is cleared in
/// memory, ``SessionEvent/signedOut(reason:)`` was emitted, the delete of the stored credential is queued and
/// the revocation has its turn behind the ended session's in-flight requests. A new session can start right
/// away: the pending revocation neither waits for it nor changes it, and the queued delete runs before any
/// save of the new session. One trace remains: if that delete fails, ``SessionEvent/storageFailed`` is emitted
/// when it does, which can be after the ``SessionEvent/signedIn`` of the new session.
///
/// Copies share the same sign-out. ``result`` may be read any number of times, from any task.
public struct PendingSignOut: Sendable {
    let deletion: Task<Bool, Never>
    /// The revocation outcome, as limited by the sign-out's wait; `nil` when nothing is revoked.
    let revocation: Completion<RevocationOutcome>?

    /// Waits for the store delete and the revocation and reports both, like `Task.value`.
    ///
    /// The revocation is best effort (RFC 7009 §2.2): the wait ends after ``OAuthClient/revocationTimeLimit``
    /// with ``RevocationOutcome/timedOut``, counted from when the delete finished, whether or not anyone reads
    /// this. Every reader gets the same outcome, except that a reader whose task is cancelled while it waits
    /// for the revocation gets ``RevocationOutcome/cancelled``; the revocation and other readers carry on. The
    /// wait for the delete is not interrupted, because its outcome is part of the result.
    public var result: SignOutResult {
        get async {
            let isDeleted = await deletion.value
            guard let revocation else {
                return SignOutResult(isStoredCredentialDeleted: isDeleted, revocation: .skipped)
            }
            let outcome: RevocationOutcome
            do {
                outcome = try await revocation.wait()
            } catch {
                outcome = .cancelled
            }
            return SignOutResult(isStoredCredentialDeleted: isDeleted, revocation: outcome)
        }
    }
}
