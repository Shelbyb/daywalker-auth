---
title: Frontend API
description: HTTP endpoints the browser calls. The SDK wraps all of these.
---

You rarely call these yourself; the SDK does. They're documented so you can debug, or build a client in another language.

**Every request needs:**
- `x-publishable-key: pk_…` header (or `?pk=` query).
- `credentials: "include"`, so the refresh cookie is sent.
- An `Origin` that is the auth service itself or on the instance's allowed origins. Other origins get `403` on anything except `GET`.
- `content-type: application/json` for bodies.

## Sign up

```http
POST /v1/client/sign_up
{ "email": "ada@example.com", "password": "…", "firstName": "Ada", "lastName": "Lovelace" }
```

`201` → `{ user, sessionId, jwt }` and sets the refresh cookie.
Errors: `email_taken` (409), `password_too_short` (400), validation (422).

## Sign in

```http
POST /v1/client/sign_in
{ "email": "ada@example.com", "password": "…" }
```

`200` → `{ user, sessionId, jwt }` and sets the refresh cookie.
Errors: `invalid_credentials` (400, same for unknown email and wrong password), `forbidden` (403, banned), `rate_limited` (429).

## Get a fresh token

```http
POST /v1/client/session/token
```

`200` → `{ jwt, sessionId, userId }`. `401` when the session has ended.

## Current session

```http
GET /v1/client/session
```

`200` → `{ session: { id, expiresAt }, user }` or `{ session: null, user: null }`.

## Sign out

```http
DELETE /v1/client/session
```

`200` → `{ ok: true }` and clears the cookie.

## Email verification (signed in)

```http
POST /v1/client/email/send_code
POST /v1/client/email/verify   { "code": "123456" }
```

## Password reset

```http
POST /v1/client/password/forgot  { "email": "ada@example.com" }
POST /v1/client/password/reset   { "email": "…", "code": "123456", "password": "…" }
```

`forgot` always returns `200 { sent: true }`. `reset` returns `200 { reset: true }`, revokes all the user's sessions and clears the cookie.

## Public keys

```http
GET /i/{instanceId}/.well-known/jwks.json
GET /i/{instanceId}/.well-known/openid-configuration
```

Both are public, cacheable for 5 minutes, and allow any origin.

## Rate limits

| Endpoint | Limit |
|---|---|
| sign_in | 20 / 5 min per IP **and** 10 / 15 min per email |
| sign_up | 10 / hour per IP |
| session/token | 120 / min per IP |
| email/send_code | 5 / hour per user |
| email/verify | 20 / 15 min per IP |
| password/forgot | 10 / hour per IP, 5 / hour per email (silently) |
| password/reset | 20 / 15 min per IP |
