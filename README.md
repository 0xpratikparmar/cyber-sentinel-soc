# CyberSentinel SOC

An AI-assisted defensive security portfolio project: a local authenticated SOC console and rule-based SIEM lab. This is an industry-oriented foundation, not an enterprise-ready product.

## Quick start (Node.js 22.13+)
No npm dependencies are required. Node SQLite may print an experimental warning.

```bash
# Bash or Zsh: enter a unique password without echoing it
printf 'New password (12+ characters): '
read -rs SOC_PASSWORD
printf '\n'
export SOC_PASSWORD
node server/start.mjs create-user analyst@example.test
unset SOC_PASSWORD
npm start
```

Open http://127.0.0.1:8000 and sign in with the account just created. Run `npm test`. The browser-only demo remains accessible at /demo; it does not send imported logs to the backend.

## Architecture
Browser console → same-origin HTTP API → session authorization → detection engine → SQLite investigation storage.
- Salted scrypt password hashes, opaque 256-bit session cookies, hashed session storage, 8-hour expiration and server-side logout.
- Origin checks, basic in-process login rate limiting, parameterized database queries and user-scoped records.
- JSONL batch import (2 MB, up to 10,000 valid events), detection, saved investigations and alert review.
- Detection rules and synthetic demo remain in engine.mjs; rules are heuristic and scoped to each imported batch.
- Tests cover existing detection rules, password hashing, session expiry, unauthorized access, origin rejection, data isolation and logout.

See [authentication and threat model](docs/AUTHENTICATION.md) for the credential and request flow.

## Log example
```json
{"timestamp":"2026-01-01T09:00:00Z","source":"192.0.2.15","type":"login_failed","user":"demo-user"}
```
Use only synthetic or authorized logs. This is not real-time monitoring. No automated remediation, external intelligence, MFA, RBAC, distributed ingestion or production deployment is included yet. Logs are stored locally in plaintext. The default server is loopback-only; do not expose it publicly without hardening. Review and extend AI-assisted code before presenting it as independent work.
