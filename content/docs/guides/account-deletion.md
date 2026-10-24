---
title: Account deletion and data export
description: Let users delete their own account (with re-authentication and a grace period) and download their data.
---

# Account deletion and data export

Both features are on by default and appear in the **Your data** card of the hosted account page. Nothing to build on your side.

## Re-authentication

Deleting or exporting needs proof of identity in the request itself, so a stolen session is not enough:

| Account has | The user sends |
|---|---|
| a password | `password` |
| two-factor | `code` (authenticator, text message or backup code), or has confirmed with a security key in this session |
| neither (social or passkey sign-in only) | `emailCode`, from `POST /v1/client/me/reauth_code` |

`GET /v1/client/me/reauth_code` returns `{ password, twoFactor, emailCode }` so a UI knows what to ask for. Wrong answers count toward [account lockout](/docs/guides/account-lockout). Not available while a platform operator is impersonating the user.

## Deleting an account

```http
POST /v1/client/me/delete      { "password": "…", "code": "…", "emailCode": "…" }
→ { "scheduledFor": "2026-11-07T10:00:00.000Z", "deleted": false }
```

1. The account is scheduled for deletion after a **grace period** (default 14 days, `0` to 90; `0` deletes at once).
2. Every session is signed out, this device included. Sign-in is refused with `403 account_pending_deletion` (after the correct password, so the response never reveals whether an email has an account).
3. The user gets an email with a single-use **cancel link** (`/cancel-deletion`, token in the URL fragment, stored only as a SHA-256). Using it cancels the deletion; the user then signs in as usual.
4. When the grace period ends, a purge job (runs every 10 minutes inside the server, safe on several servers) deletes the user and everything that cascades from them, deletes organizations they were the **only** member of, and removes the detail (IP addresses, browsers) from their audit events. The events themselves remain.

A user who is the **only admin of an organization that has other members** gets `409 sole_org_admin`: they must make someone else an admin, or delete the organization, first.

Webhooks: `user.deletion_requested`, `user.deletion_canceled`, then `user.deleted` when the purge happens. Audit events: `user.deletion_requested`, `user.deletion_canceled`, `user.deleted`.

### Settings (backend API)

```http
GET   /v1/instance/account_deletion     → { "enabled": true, "graceDays": 14 }
PATCH /v1/instance/account_deletion     { "enabled": false }   // or { "graceDays": 30 }
```

When disabled, `POST /v1/client/me/delete` returns `403 account_deletion_disabled`.

### Canceling as a developer

```http
POST /v1/users/{userId}/cancel_deletion  → { "id": "usr_…", "canceled": true }
```

`canceled` is `false` when nothing was pending. In the SDK: `backend.users.cancelDeletion(id)`.

## Data export

```http
POST /v1/client/me/export     { "password": "…" }
```

Returns a JSON file (`Content-Disposition: attachment`, `Cache-Control: no-store`) with: profile, email addresses, connected accounts, two-factor and passkey metadata, sessions (device and IP, decrypted for the user), organizations, accepted legal versions and their activity log. Fields are decrypted for the user. Never included: password hash, authenticator secret, backup codes, token hashes, or your application's private metadata.

Limit: 3 exports per hour per user. Each export is recorded as `user.data_exported` in the audit log.

## SDK

```ts
const need = await client.getReauthRequirements();   // { password, twoFactor, emailCode }
await client.sendReauthCode();                       // only when need.emailCode
const data = await client.exportData({ password });
const { scheduledFor } = await client.deleteAccount({ password });
await client.cancelAccountDeletion(tokenFromEmailLink);
```

## Email template

The `account_deletion` template (variables `link`, `date`) and `reauth_code` (`code`, `expires_minutes`) can be edited like the others; see [Email templates](/docs/guides/email-templates).
