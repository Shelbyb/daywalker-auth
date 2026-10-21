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

## Revoke a session

```http
POST /v1/sessions/{sessionId}/revoke
```

`200` → `{ "id": "sess_…", "status": "revoked" }`

## Example with curl

```bash
curl https://auth.daywalker.dev/v1/users?limit=5 \
  -H "Authorization: Bearer $DAYWALKER_SECRET_KEY"
```
