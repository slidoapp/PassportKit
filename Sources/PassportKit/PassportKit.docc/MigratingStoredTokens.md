# Migrating stored tokens

Keep users signed in when an app replaces its previous OAuth library with PassportKit.

## Overview

A user who is signed in with the previous library has a refresh token in
storage. If the app discards it, that user has to sign in again.
``KeychainCredentialStore`` reads and writes only its own format, so it does
not read the old library's item. The app reads that token itself, hands it
to ``TokenManager/signIn(refreshToken:grantedScope:idToken:)`` and removes
the old item once the new session works.

## The procedure

On launch, before anything asks for a token:

1. Create the ``TokenManager`` with a ``CredentialAccount`` that differs
   from the old item's service and account, so the old item is never
   overwritten.
2. Call ``TokenManager/load()``. A session saved by an earlier launch is
   restored.
3. If the previous library's item still exists, read its refresh token with
   that library or with your own code.
4. If there is no session yet, call
   ``TokenManager/signIn(refreshToken:grantedScope:idToken:)``. It saves the
   credential and sends nothing.
5. Ask for an access token. That is the first request with the migrated
   token, and it saves the rotated refresh token.
6. Only when step 5 succeeded, delete the old item.

```swift
func migratedManager(client: OAuthClient) async throws -> TokenManager {
    // A different service than the old item used.
    let account = CredentialAccount(service: "com.example.app.passportkit", account: "default")
    let manager = TokenManager(client: client, store: KeychainCredentialStore(), account: account)
    _ = try await manager.load()

    guard let legacyRefreshToken = loadLegacyRefreshToken() else { return manager }
    if await manager.credential == nil {
        await manager.signIn(refreshToken: Secret(legacyRefreshToken), grantedScope: ["openid", "offline_access"])
    }
    do {
        _ = try await manager.accessToken()
        deleteLegacyItem()
    } catch {
        // Keep the old item: a transient failure must not sign the user out. The next launch tries again.
    }
    return manager
}
```

`loadLegacyRefreshToken()` and `deleteLegacyItem()` are yours: they read and
remove whatever the previous library stored. The old access token is not
carried over, because its expiry is unknown; the first
``TokenManager/accessToken(for:)`` refreshes.

## Pitfalls

- **Configure the client as before.** The migrated token belongs to a
  client ID and an issuer. ``TokenManager/load()`` ignores a stored credential
  of another client or issuer, so use the same ``ClientConfiguration`` values
  as the previous library did.
- **Do not delete the old item first.** Until the first token request
  succeeded, nothing proves the refresh token still works. If the request
  fails because the network is down, the old item is what lets the next
  launch try again. If the server answers `invalid_grant`, the session ends
  and the user has to sign in; the old token is dead and can be removed.
- **Migration is one way.** PassportKit stores its credential in its own
  format and under its own account, and the old build reads only the old
  item. Rolling back to an older build of your app signs those users out once
  the old item is deleted, and a refresh token that rotated is no longer valid
  there anyway.
- **Test with a real item.** Before you ship, write an item with your
  previous library on a device or simulator and run the migration against it.
