import Foundation
import HTTPTypes

extension OAuthClient {
    /// The time limit ``TokenManager/signOut(revoke:)`` gives the revocation, for
    /// ``revoke(_:typeHint:timeLimit:)``: five seconds.
    public static let defaultRevocationTimeLimit = Duration.seconds(5)

    /// Revokes a token (RFC 7009 §2).
    ///
    /// Any 2xx response is success regardless of its body (§2.2: unknown or already revoked tokens also
    /// answer 200). A 503 is reported as ``PassportError/Code-swift.struct/temporarilyUnavailable`` with
    /// `Retry-After` honoured (§2.2.1). Throws `invalidConfiguration` when no revocation endpoint is configured.
    public func revoke(_ token: Secret, typeHint: TokenTypeHint? = nil) async throws {
        var request = FormRequest(
            endpoint: .revocation,
            url: try requireEndpoint(configuration.endpoints.revocation, name: "revocation")
        )
        request.add(OAuthParameter.token, token.reveal())
        if let typeHint { request.add(OAuthParameter.tokenTypeHint, typeHint.rawValue) }
        let (response, body) = try await send(request)
        guard response.status.kind == .successful else {
            throw failure(response, body: body, to: request, context: .other)
        }
    }

    /// Revokes a token best effort and gives up after `timeLimit` on the client's clock (RFC 7009 §2).
    ///
    /// For a token that never became a session, for example a refresh token the app obtained but did not hand
    /// to a ``TokenManager``, so it can be invalidated at the server without holding up the app. Revocation is
    /// a courtesy to the server, and the token may still be valid whatever the outcome (RFC 7009 §2.2).
    ///
    /// Never throws. Returns ``SignOutResult/Revocation/revoked`` for any 2xx (§2.2),
    /// ``SignOutResult/Revocation/failed(_:)`` with the error ``revoke(_:typeHint:)`` would throw,
    /// ``SignOutResult/Revocation/timedOut`` when `timeLimit` passed first, ``SignOutResult/Revocation/cancelled``
    /// when the calling task was cancelled, and ``SignOutResult/Revocation/skipped`` when no revocation endpoint
    /// is configured. A timeout or cancellation cancels the request; it may still have reached the server.
    ///
    /// ``defaultRevocationTimeLimit`` is the limit ``TokenManager/signOut(revoke:)`` uses.
    public func revoke(
        _ token: Secret, typeHint: TokenTypeHint? = nil, timeLimit: Duration
    ) async -> SignOutResult.Revocation {
        guard configuration.endpoints.revocation != nil else { return .skipped }
        do {
            let finished = try await withTimeLimit(timeLimit, clock: clock) {
                try await revoke(token, typeHint: typeHint)
                return true
            }
            return finished == nil ? .timedOut : .revoked
        } catch is CancellationError {
            return .cancelled
        } catch {
            return .failed(error as? PassportError ?? PassportError(.transportFailure, underlying: error))
        }
    }
}
