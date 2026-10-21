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

## Organizations

| Endpoint | Description |
| --- | --- |
| `GET /v1/organizations?limit=&offset=` | List organizations in your instance |
| `GET /v1/organizations/{orgId}/members` | Members as `{ userId, role, joinedAt }` |
