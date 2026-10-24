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

## Machine tokens and API keys

`verifyMachineToken(token, { ...config, scopes? })`, `verifyApiKey(key, { secretKey, apiUrl, scopes? })` and `requestMachineToken({ apiUrl, clientId, clientSecret, scopes? })`. The backend client has `m2mClients` and `apiKeys`. See [Machine auth and API keys](/docs/guides/machine-auth).

## Test helpers

`testEmail(name, { unique, domain })`, `testPhone(index)`, `isTestEmail`, `isTestPhone` and `TEST_CODE` for [end-to-end tests](/docs/guides/test-mode); `backend().testMode.get()` / `.set(enabled)` toggles test mode on a development instance.

## Organization claims and API

`verifyToken()` also returns `orgId` and `orgRole` (`"admin"`, `"member"` or a custom role key) and `orgPermissions` when the session has an active organization. `has(claims, { permission?, role? })` and `protect(claims, check)` (throws `ForbiddenError`, status 403) test them; `organizationRoles` and `organizationDomains` on the backend client manage roles and domains. See [Roles, permissions and domains](/docs/guides/organization-roles). The backend client adds `organizations.list({ limit, offset })` and `organizations.members(orgId)`. See the [Organizations guide](/docs/guides/organizations).

## Step-up authentication

`verifyToken()` also returns `authTime` and `fva`. `requireRecentAuth(claims, { maxAge, level })` throws `ReverificationRequiredError` (status 403; `toResponse()` builds the 403 JSON the browser SDK reacts to), `isRecentlyVerified(claims, check)` returns a boolean, and `reverificationResponse(check)` builds the response directly. `maxAge` is in seconds; `level` is `first_factor` (default), `second_factor` or `multi_factor`. See [Step-up authentication](/docs/guides/step-up-auth).

## Device-bound sessions

`verifyToken()` returns `deviceKey` (the key thumbprint, from the `cnf.jkt` claim) for sessions bound to a browser key. See [Device-bound sessions](/docs/guides/device-binding).

## Audit log integrity

`createBackendClient` exposes `auditEvents.verify()`, `auditEvents.exportText({ from, to })` and the `auditExport` client (`get`, `set`, `remove`, `test`, `push`). `verifyAuditExport(ndjson, { after, expectedHead })` checks an exported file offline with no key. See [Tamper-evident audit log](/docs/guides/audit-integrity).

## Webhooks

`verifyWebhook(rawBody, headers, secret, { toleranceSeconds? })` verifies a webhook request and returns the parsed event, or throws `WebhookVerificationError`. The backend client adds `webhooks.list`, `get`, `create`, `update`, `delete`, `rotateSecret`, `deliveries`, `sendTest` and `retry`. See the [Webhooks guide](/docs/guides/webhooks).
