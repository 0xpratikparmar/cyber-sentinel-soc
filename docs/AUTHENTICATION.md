# Authentication and data flow

## Components
- console.mjs: same-origin browser client; never reads or stores session token in JavaScript.
- server/http.mjs: HTTP API, origin verification, login throttle, cookie issuance, authorization.
- server/auth.mjs: salted scrypt password derivation, constant-time comparison, random opaque session tokens and SHA-256 token digest.
- server/store.mjs: SQLite users, sessions and owner-scoped investigation batches, parameterized SQL.

## Request flow
1. An operator account is provisioned locally through the CLI. No public registration or default password exists.
2. POST /api/login with email and password as JSON. Server checks Origin, rate limits by peer IP and verifies the scrypt hash.
3. Server generates a random 256-bit session token; only its SHA-256 digest and expiry are stored in SQLite. The browser receives an HttpOnly, SameSite=Strict cookie (Secure when HTTPS origin configured).
4. Browser automatically attaches the cookie to same-origin API requests. Server hashes the token and looks up a non-expired session, then scopes batch access to the authenticated user's ID.
5. POST /api/logout deletes the session and clears the cookie. Sessions expire after eight hours. Login replaces the current cookie session.
6. Credentials and session tokens are not returned in API JSON or persisted in browser localStorage.

## Threat model and limits
This is a local lab, not production-certified. The default HTTP listener binds to loopback; remote deployments require a correctly configured TLS reverse proxy, trusted proxy handling, distributed rate limits, MFA or external OIDC, audit logs, user lifecycle, encrypted backups, data retention and security review. Rate limits are in memory; a reverse proxy shares its peer address across clients. The database stores log text and alerts in plaintext; protect the data directory and use only authorized logs. Never commit passwords, session tokens or database files. No refresh token or JWT is needed for this server-side session model.
