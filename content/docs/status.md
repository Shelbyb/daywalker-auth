# Status and health checks

Two public, unauthenticated endpoints tell you whether the service is working.

## Status page

[`/status`](/status) shows each component as **Operational**, **Degraded** or **Outage**, and refreshes every minute. It is the page to look at when something seems wrong.

## `GET /v1/health`

For monitors, load balancers and your own dashboards:

```json
{
  "status": "ok",
  "components": {
    "database": "ok",
    "valkey": "ok",
    "email": "ok",
    "jobs": "ok",
    "signingKeys": "ok"
  },
  "checkedAt": "2026-10-24T12:00:00.000Z"
}
```

Each value is `ok`, `degraded` or `down`. The HTTP status is `200` for `ok` and `degraded` (still serving) and `503` for `down`.

| Component | What it checks | When it is not ok |
| --- | --- | --- |
| `database` | A query to Postgres succeeds within 2 seconds | `down`: nothing can be read or written |
| `valkey` | The cache answers `PING` within 2 seconds | `down`: sessions, rate limits and codes don't work |
| `email` | A mail transport is configured (a Resend key in production) | `degraded`: sign-in codes, invitations and resets aren't delivered |
| `jobs` | The background job loop (webhook delivery, cleanup) has run within the last 90 seconds, on any instance | `degraded`: webhooks aren't being delivered or retried |
| `signingKeys` | An active signing key exists **and decrypts with the current `MASTER_KEY`** | `degraded`: no instance created yet; `down`: tokens can't be issued, usually a wrong `MASTER_KEY` |

The overall `status` is `down` if the database, cache or token signing is down, `degraded` if anything else isn't ok, otherwise `ok`.

### What it deliberately doesn't tell you

Only the levels above. No versions, hostnames, connection strings, latencies, counts, error messages, provider names or instance IDs, and no credentials are needed or accepted. A failing check says *that* it failed, not why: look in the service logs for the reason. The result is shared for 5 seconds between callers, and one client address may make 120 requests a minute (then `429`).

### Which check to use where

- **Platform health check (restart the container if it fails):** `GET /healthz`. It only proves the process answers, so a database blip doesn't restart healthy containers.
- **External uptime monitor:** `GET /v1/health`, alerting on a non-200 response. Also alert on `"status": "degraded"` lasting more than a few minutes, which is how a stopped job loop or a missing email key shows up.
- `GET /healthz?deep=1` remains as a minimal database-and-cache check.
