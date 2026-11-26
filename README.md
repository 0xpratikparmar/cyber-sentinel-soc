# CyberSentinel SOC

An educational, browser-local mini-SIEM for structured security logs. Built as an AI-assisted portfolio project for hands-on study and extension by [0xpratikparmar](https://github.com/0xpratikparmar).

## Features
- Synthetic demo with 128 events; local JSONL import (2 MB limit), validation and rejected-row counts.
- Rule-based repeated-login-failure detection per source/user in a five-minute window; success after failures, access denial and file-change alerts.
- Dashboard metrics, event distribution, severity and text filters, JSON alert export.
- No backend, accounts, dependencies or external telemetry; no live ingestion or automated remediation.

## Run locally
From this directory, run `python3 -m http.server 8000 --bind 127.0.0.1`, then open http://127.0.0.1:8000. Run tests with Node.js 22: `node --test engine.test.mjs`.

## Architecture
`JSONL / demo → validation and normalization → detection rules → dashboard → JSON export`.
`engine.mjs` contains pure logic; `app.mjs` renders using textContent; CSS provides responsive layout. No real attack logs are shipped. Demo IPs are documentation ranges.

## Input format
One JSON object per line. Required fields: `timestamp` (ISO timestamp), `source` (string), `type` (`login_failed`, `login_success`, `access_denied`, `file_changed`, or `network_event`). Optional `user` and `detail` strings.

```json
{"timestamp":"2026-01-01T09:00:00Z","source":"192.0.2.15","type":"login_failed","user":"demo-user"}
```

## Limitations and responsible use
Alerts are heuristic indicators, not confirmed attacks. No real-time log collection, threat intelligence feed, IP geolocation, malware analysis, persistence or enterprise security guarantees. Use only synthetic or authorized logs. Export may contain sensitive data; do not upload it publicly. This is a learning project, not a production SIEM. Review and extend the code before presenting it as independent work.
