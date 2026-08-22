# Session security contract

## Token model

Successful login creates one durable session and returns a 15-minute access JWT
plus a 256-bit opaque refresh token. Access JWTs are signed only with RS256 and
carry `kid`, `iss`, `aud`, `sub`, `jti`, `sid`, `iat`, `exp`, and
`token_type=access`. Validation fixes the algorithm and requires the configured
known key ID, issuer, audience, type, bounded clock skew, and an active matching
server-side session.

The refresh token is a bearer secret. Only its SHA-256 digest is persisted.
`POST /api/auth/refresh` consumes the presented token under a database write
lock and returns a new pair. A consumed token can never succeed twice. Reuse is
treated as possible theft and revokes the complete session, including tokens
issued by the first rotation. Unknown, expired and revoked refresh tokens use a
separate stable error from detected reuse, without returning token or database
details.

`POST /api/auth/logout` derives the session from a valid access token and marks
it revoked. Every access-token validation checks that state, providing immediate
server logout rather than waiting for JWT expiry.

## Trust boundaries and client ownership

The authentication service returns token material to its trusted gateway
caller. It does not set browser cookies and does not authorize browser storage.
CLIENT-02/03 and UMG-05 own the same-origin BFF design: refresh material must be
kept out of JavaScript-readable storage and transported using Secure, HttpOnly,
appropriate SameSite cookies with CSRF controls. Access tokens should remain
server-side or in memory for the shortest practical period.

Never log request/response bodies on login or refresh routes, token hashes,
complete JWTs, refresh tokens, signing keys, or session IDs. Operational events
should use correlation IDs and stable error codes.

## Rotation and recovery

Change `JWT_KEY_ID` whenever the signing key changes. The service signs only
with the active RSA private key and publishes active plus configured previous
public keys at `/.well-known/jwks.json`. Keep an old public key through the
maximum token lifetime, skew and downstream JWKS cache window, then remove it.
A private-key compromise requires a new pair and revocation of affected sessions;
never configure an old private key as overlap material. The platform owner
supplies private material through the secret manager and keeps clocks
synchronized.

Refresh lifetime is an absolute session boundary and does not slide during
rotation. A legitimate concurrent double refresh intentionally revokes the
family, requiring a fresh login. This fail-closed behavior trades convenience
for replay protection.
