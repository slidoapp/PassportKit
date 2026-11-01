/// A sign-out whose local part is done and whose store delete and revocation (RFC 7009 §2) may still run.
///
/// Returned by ``TokenManager/beginSignOut(revoke:)``. By the time you hold one, the session is cleared in
/// memory, ``SessionEvent/signedOut(reason:)`` was emitted, the delete of the stored credential is queued and
/// the revocation has its turn behind the ended session's in-flight requests. A new session can start right
/// away: nothing that is still pending touches it.
///
/// Copies share the same sign-out. ``result()`` may be called any number of times, from any task.
public struct PendingSignOut: Sendable {
    let deletion: Task<Bool, Never>
    /// The revocation outcome, as limited by the sign-out's wait; `nil` when nothing is revoked.
    let revocation: Completion<SignOutResult.Revocation>?

    /// Waits for the store delete and the revocation and reports both.
    ///
    /// The revocation is best effort (RFC 7009 §2.2): the wait ends after
    /// ``OAuthClient/defaultRevocationTimeLimit`` with ``SignOutResult/Revocation/timedOut``, counted from when
    /// the delete finished, whether or not anyone calls this. Cancelling the calling task while it waits for the
    /// revocation returns ``SignOutResult/Revocation/cancelled`` to that caller only; the revocation carries on.
    /// The wait for the delete is not interrupted, because its outcome is part of the result.
    public func result() async -> SignOutResult {
        let isDeleted = await deletion.value
        guard let revocation else { return SignOutResult(isStoredCredentialDeleted: isDeleted, revocation: .skipped) }
        let outcome: SignOutResult.Revocation
        do {
            outcome = try await revocation.wait()
        } catch {
            outcome = .cancelled
        }
        return SignOutResult(isStoredCredentialDeleted: isDeleted, revocation: outcome)
    }
}
