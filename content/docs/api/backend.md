---
title: Backend API
description: Server-to-server endpoints authenticated with your secret key.
---

```http
Authorization: Bearer sk_test_…
```

- These endpoints send **no CORS headers**, so browsers can't call them.
- Every response is `Cache-Control: no-store`.
- In JavaScript, use the [backend client](/docs/sdk/server#createbackendclient-options) instead of calling them directly.

## List users

```http
GET /v1/users?limit=20&offset=0
```

```json
{ "data": [ { "id": "user_…", "emailAddresses": [ … ], "privateMetadata": {}, "banned": false, … } ] }
```

## Get a user

```http
GET /v1/users/{userId}
```

`404` if the user doesn't exist in this instance.

## Delete a user

```http
DELETE /v1/users/{userId}
```

`200` → `{ "id": "user_…", "deleted": true }`. Also deletes emails, password and sessions.

## Remove a user's two-factor authentication

```http
DELETE /v1/users/{userId}/mfa
```

For users locked out of both their authenticator and backup codes. **Verify their identity first.** `200` → `{ id, twoFactorEnabled: false }`

## Unlock a locked account

```http
POST /v1/users/{userId}/unlock
```

Lifts an [account lockout](/docs/guides/account-lockout) and resets its progression. `200` → `{ id, unlocked }` (`unlocked` is `false` when the account wasn't locked). The user object from `GET /v1/users/{id}` has `lockedUntil`.

### Cancel a pending deletion

```http
POST /v1/users/{userId}/cancel_deletion
```

Stops a [self-service deletion](/docs/guides/account-deletion). `200` → `{ id, canceled }`. `GET`/`PATCH /v1/instance/account_deletion` read and set `{ enabled, graceDays }`.

`GET`/`PATCH /v1/instance/device_binding` read and set `{ mode }` (`off`, `optional`, `required`) for [device-bound sessions](/docs/guides/device-binding).

## Organization roles, members and domains

| Request | What it does |
| --- | --- |
| `GET /v1/organization_roles` | Built-in and custom roles with permissions |
| `POST /v1/organization_roles` | `{ key, name, description?, permissions[] }` |
| `GET\|PATCH\|DELETE /v1/organization_roles/{key}` | Read, edit or delete (409 `role_in_use`) |
| `PATCH /v1/organizations/{orgId}/members/{userId}` | `{ role }` (built-in or custom) |
| `GET\|POST /v1/organizations/{orgId}/domains` | List, or claim `{ domain }` |
| `POST /v1/organizations/{orgId}/domains/{id}/verify` | `{ method: "dns" }`, `{ method: "email", mailbox }`, `{ method: "email", code }` |
| `PATCH\|DELETE /v1/organizations/{orgId}/domains/{id}` | `{ enrollment: "none"\|"suggest"\|"auto_join", role? }`, or remove |

See [Roles, permissions and domains](/docs/guides/organization-roles).

## Audit log integrity and export

- `GET /v1/audit_events/verify` checks the hash chain and returns `{ ok, checked, head, problem? }`.
- `GET /v1/audit_events/export?from=&to=` streams the log as NDJSON.
- `GET|PUT|DELETE /v1/instance/audit_export` reads, sets or removes the bucket export; `POST /v1/instance/audit_export/push` uploads now and `POST /v1/instance/audit_export/test` writes a test object. Credentials are write-only.

See [Tamper-evident audit log](/docs/guides/audit-integrity).

## Revoke a session

```http
POST /v1/sessions/{sessionId}/revoke
```

`200` → `{ "id": "sess_…", "status": "revoked" }`

## Configure a social provider

```http
PUT /v1/instance/oauth/{google|github}
{ "clientId": "…", "clientSecret": "…", "enabled": true }
```

`200` → `{ provider, enabled, clientId, redirectUri }`. The secret is encrypted at rest and never returned. `redirectUri` is the callback URL to register with the provider.

## Require terms at sign-up

```http
PUT /v1/instance/legal
{ "required": true, "termsUrl": "https://…", "privacyUrl": "https://…", "version": "2026-10-21" }
```

See [Require terms at sign-up](/docs/guides/terms-acceptance).

## Example with curl

```bash
curl https://users.daywalker.dev/v1/users?limit=5 \
  -H "Authorization: Bearer $DAYWALKER_SECRET_KEY"
```

## Enterprise SSO and SCIM

| Endpoint | Description |
| --- | --- |
| `GET` / `POST /v1/saml_connections` | List or create SAML connections (`name`, `domains`, `organizationId?`, `metadataXml` or `idpEntityId` + `ssoUrl` + `certificates`) |
| `GET` / `PATCH` / `DELETE /v1/saml_connections/{id}` | Read, update, delete. `PATCH` accepts `enabled`, `ssoRequired`, `scimAdminGroups`, `sloUrl` and `singleLogout` |
| `POST /v1/saml_connections/{id}/scim_token` | Turn on SCIM provisioning. Returns the token **once**; calling again replaces it |
| `DELETE /v1/saml_connections/{id}/scim_token` | Turn SCIM off and revoke the token |

The identity provider itself calls `/v1/scim/v2/{connectionId}/Users` and `/Groups` with the SCIM token. See [Enterprise SSO](/docs/guides/enterprise-sso).

## Sign-up protection and two-factor policy

| Endpoint | Description |
| --- | --- |
| `GET /v1/instance/protection` | Email rules, the Turnstile site key (never the secret) and the two-factor requirement |
| `PATCH /v1/instance/protection` | Any of `allowedDomains`, `blockedDomains`, `blockDisposableEmails`, `captcha` (`{ siteKey, secretKey }` or `null`), `requireTwoFactor`, `twoFactorGraceDays` |

## Organizations

| Endpoint | Description |
| --- | --- |
| `GET` / `PATCH /v1/organizations/{orgId}` | One organization; `PATCH { requireTwoFactor }` |
| `GET /v1/organizations?limit=&offset=` | List organizations in your instance |
| `GET /v1/organizations/{orgId}/members` | Members as `{ userId, role, joinedAt }` |

## Webhooks

| Endpoint | Description |
| --- | --- |
| `GET /v1/webhooks` | List endpoints |
| `POST /v1/webhooks` | Create `{ url, events?, description? }`. Returns the signing `secret` once |
| `GET` / `PATCH` / `DELETE /v1/webhooks/{id}` | Read, update (`url`, `events`, `description`, `enabled`), delete |
| `POST /v1/webhooks/{id}/rotate_secret` | New signing secret; the old one stops working |
| `GET /v1/webhooks/{id}/deliveries?limit=` | Delivery log (status, attempts, errors) |
| `POST /v1/webhooks/{id}/test` | Send a `webhook.test` event |
| `POST /v1/webhooks/deliveries/{deliveryId}/retry` | Re-queue a delivery |

See the [Webhooks guide](/docs/guides/webhooks).

`GET /v1/instance/environments` returns this instance's environment and its application's others. `POST /v1/instance/clone` (production secret key) copies configuration from development; see [Development and production](/docs/guides/environments).

`/v1/m2m_clients` (list, create, `GET|PATCH|DELETE /{id}`, `POST /{id}/rotate_secret`) manage machine clients; `POST /v1/m2m/token` is the public OAuth token endpoint. `/v1/api_keys` (list, create, `GET|DELETE /{id}`, `POST /verify`) and `GET|PATCH /v1/instance/api_keys` manage keys held by your users and organizations. See [Machine auth and API keys](/docs/guides/machine-auth).
