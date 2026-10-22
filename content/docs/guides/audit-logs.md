---
title: Audit logs
description: See who signed in, what failed, and what changed in your instance.
---

# Audit logs

Every instance keeps an audit log: a record of sign-ins, failed attempts, security changes and settings changes. Use it to answer questions like "did someone try to break into this account?" or "who rotated our keys?".

Events are kept for **90 days**. Details that could identify a person (IP addresses, browsers, key names) are stored encrypted.

## In the dashboard

Open your instance and choose **Audit log**. Filter by event type, or click any target ID to see everything that happened to that user, key or webhook.

## From your backend

```ts
import { createBackendClient } from "@daywalker/auth/server";

const daywalker = createBackendClient({
  secretKey: process.env.DAYWALKER_SECRET_KEY!,
  apiUrl: "https://users.daywalker.dev",
});

// Newest first
const page = await daywalker.auditEvents.list({ type: "user.sign_in_failed", limit: 50 });
for (const e of page.data) console.log(e.createdAt, e.type, e.target, e.data);

// Next page
if (page.nextCursor) await daywalker.auditEvents.list({ before: page.nextCursor });
```

Or with plain HTTP: `GET /v1/audit_events?type=&target=&before=&limit=` with `Authorization: Bearer <secret key>`.

Each event looks like this:

```json
{
  "id": "aud_…",
  "type": "user.signed_in",
  "actor": { "type": "user", "id": "user_…" },
  "target": "user_…",
  "data": { "sessionId": "sess_…", "ip": "203.0.113.9", "userAgent": "Mozilla/5.0 …" },
  "createdAt": "2026-10-22T14:03:11.000Z"
}
```

`actor.type` is who did it: `user` (the person themselves), `developer` (someone in the dashboard), `api` (your backend, with a secret key) or `system`.

## Events

| Group | Events |
| --- | --- |
| Sign-in | `user.signed_up`, `user.signed_in`, `user.signed_out`, `user.sign_in_failed`, `user.sign_in_blocked`, `user.two_factor_failed` |
| Account security | `user.password_changed`, `user.password_reset`, `user.profile_updated`, `user.two_factor_enabled`, `user.two_factor_disabled`, `user.two_factor_reset`, `user.passkey_added`, `user.passkey_removed` |
| User management | `user.banned`, `user.unbanned`, `user.deleted` |
| Keys | `api_key.created`, `api_key.revoked`, `signing_key.rotated` |
| Settings | `instance.settings_updated`, `instance.terms_updated`, `social_provider.saved`, `social_provider.enabled`, `social_provider.disabled` |
| Webhooks | `webhook.created`, `webhook.updated`, `webhook.secret_rotated`, `webhook.deleted` |

Failed password attempts are logged only for emails that belong to a real account, so typos and scanners don't flood the log.

Audit logs are separate from [webhooks](/docs/guides/webhooks): webhooks push a few events to your server in real time; the audit log is a complete history you can query.
