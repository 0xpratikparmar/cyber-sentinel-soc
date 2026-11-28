# Enterprise-oriented SIEM operations (development release)

## Account setup and access boundary
Existing accounts migrate to analyst. Create a new admin account with the same hidden-password setup in README, using `node server/start.mjs create-user admin@example.test admin`. Admins manage collectors and view audit entries for their own account; analysts can import, search and manage their own incidents. There is no shared organization or global administrator yet. All record access remains owner-scoped.

## Collector ingestion
Sign in as admin, create a named collector, copy its one-time token securely. Only a SHA-256 token digest is stored. Set SOC_COLLECTOR_TOKEN in a private shell environment and optionally SOC_URL (defaults to loopback). Run `node agents/ship.mjs examples/sample-events.txt`. This sends only the explicitly selected normalized JSONL file, using bounded chunks, HTTPS for remote URLs, retry and per-collector content-based idempotency. Schedule or invoke it for authorized completed log files; it is not a continuous native OS agent. Identical chunks are deduplicated, changed chunk boundaries are not. Revoke tokens in the admin console when no longer needed. Machine endpoint is POST /api/collector/ingest with Authorization Bearer, Idempotency-Key and JSON jsonl. No browser credentials accepted.

## Operations dashboard
Dashboard totals and saved batches refresh every five seconds while signed in. Search indexed newly imported events by source, account or detail (latest 200 results). High alerts automatically create incidents; set open, investigating or resolved and add notes. Audit shows latest 100 account actions. Legacy batches are preserved but not backfilled into event search/incidents. Detection correlation remains batch-local; the collector uses 500-row chunks, so rules spanning chunks can be missed. No live push/SSE, log rotation agent, external intel, or automatic containment.

## Local container deployment
With Docker Compose installed, run `docker compose build`, then `docker compose run --rm -e SOC_PASSWORD soc node server/start.mjs create-user admin@example.test admin` after setting SOC_PASSWORD securely in your shell as shown in README. Unset it after creation. Run `docker compose up -d` and open http://127.0.0.1:8000. Stop with `docker compose down`; do not use -v unless intentionally deleting stored data. The container runs as non-root and the published port is loopback-only. Do not expose directly to the internet.

## Remaining production work
TLS termination and proxy trust, multi-tenant workspaces with shared incident assignment, SSO/MFA, durable distributed queues, streaming cross-batch correlation, normalized native OS connectors, OpenSearch/PostgreSQL scale-out, quotas/retention, encrypted backups, tamper-evident audit, incident notifications, independent penetration test and load/restore testing are required before production. Existing SQLite data and audit are local and plaintext. Docker and interactive UI require separate smoke tests.
