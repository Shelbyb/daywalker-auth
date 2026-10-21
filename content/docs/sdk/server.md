---
title: "@daywalker/auth/server"
description: Token verification and the backend API client for any JavaScript server.
---

Importing this module in browser code throws on purpose, so a secret key can't end up in a bundle by accident.

## `verifyToken(token, options)`

```ts
const session = await verifyToken(token, {
  publishableKey: "pk_test_…",
  frontendApi: "https://users.daywalker.dev",
  authorizedParties: ["https://app.example.com"], // optional
});
// → { userId, sessionId, issuedAt, expiresAt, azp? } | null
```

Behaviour:

- Returns `null` for missing, malformed, expired, tampered or foreign tokens.
- Accepts **only** `ES256` signatures, so `alg: none` and algorithm-swap attacks fail.
- Fetches the instance's public keys once, then caches them. When it sees a key ID it doesn't know (after key rotation), it refetches automatically.
- Throws if the keys can't be fetched, so an outage isn't mistaken for "signed out".

## `createBackendClient(options)`

```ts
const api = createBackendClient({ secretKey: process.env.DAYWALKER_SECRET_KEY!, apiUrl: "https://users.daywalker.dev" });
```

| Method | Returns |
|---|---|
| `api.users.list({ limit?, offset? })` | `BackendUser[]` |
| `api.users.get(userId)` | `BackendUser` |
| `api.users.delete(userId)` | `{ id, deleted: true }` |
| `api.sessions.revoke(sessionId)` | `{ id, status: "revoked" }` |

`BackendUser` is the public `User` plus `privateMetadata` and `banned`.

Failed calls throw `BackendError` with `status`, `code` and `message`. Passing anything other than an `sk_` key throws immediately.

## Organization claims and API

`verifyToken()` also returns `orgId` and `orgRole` (`"admin"` or `"member"`) when the session has an active organization. The backend client adds `organizations.list({ limit, offset })` and `organizations.members(orgId)`. See the [Organizations guide](/docs/guides/organizations).
