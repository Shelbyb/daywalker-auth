---
title: Machine-to-machine auth and API keys
description: Client-credentials tokens for your own services, and API keys that your users and organizations create for your API.
---

# Machine-to-machine auth and API keys

Two ways for something other than a signed-in browser session to call your API:

- **Machine clients** for your own services (cron jobs, workers, other backends). OAuth 2.0 client credentials, short-lived JWTs.
- **API keys** that your end users or organizations create to call your API (like a "personal access token").

Neither is the same as the `sk_` secret keys you use against this service's backend API.

## Machine clients

Create one in **Dashboard → Configure → Developers → Machine & API keys**, or:

```http
POST /v1/m2m_clients     { "name": "Billing worker", "scopes": ["read:invoices"], "tokenTtlSeconds": 300 }
→ { "id": "m2m_…", "clientSecret": "ms_…", … }     // the secret is shown once
```

The client ID is the `id`. Only a SHA-256 of the secret is stored. Limit: 20 clients per instance.

### Get a token

```http
POST /v1/m2m/token
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=read:invoices
→ { "access_token": "eyJ…", "token_type": "Bearer", "expires_in": 300, "scope": "read:invoices" }
```

Credentials may also be sent in the body (`client_id`, `client_secret`, form or JSON). `scope` is optional (default: all of the client's scopes) and can only narrow them. Errors follow RFC 6749: `invalid_client` (401), `invalid_scope`, `unsupported_grant_type`, `invalid_request`. Failed attempts are throttled per source address and client, so guessing is slow but a stranger can't lock your service out. The endpoint sends no CORS headers: it is for servers.

The token is an ES256 JWT (`typ: at+jwt`) signed with the instance key, so it verifies against the same JWKS as session tokens (`/i/<instance>/.well-known/jwks.json`; the discovery document lists `token_endpoint`). Lifetime is 30 to 3600 seconds (default 300). Tokens can't be revoked early: deleting a client or rotating its secret stops new tokens, and existing ones expire within their lifetime, so keep it short.

### Rotate a secret

```http
POST /v1/m2m_clients/{id}/rotate_secret   { "graceMinutes": 30 }
```

Returns a new secret. With `graceMinutes` (up to 1440) the old secret keeps working until then, so you can deploy without downtime.

### Verify in your service

```ts
import { requestMachineToken, verifyMachineToken } from "@daywalker/auth/server";

// Caller
const { accessToken } = await requestMachineToken({ apiUrl, clientId, clientSecret, scopes: ["read:invoices"] });

// Receiver
const claims = await verifyMachineToken(bearer, { publishableKey, frontendApi, scopes: ["read:invoices"] });
if (!claims) return new Response("Unauthorized", { status: 401 });
```

`verifyMachineToken` accepts only machine tokens, and `verifyToken` accepts only user session tokens, so one can't stand in for the other.

## API keys for your users and organizations

Off by default. Turn them on in the same dashboard page or with `PATCH /v1/instance/api_keys`:

```json
{ "enabled": true, "allowedScopes": ["read:items"], "maxPerSubject": 10, "maxExpiryDays": 365 }
```

Signed-in users can then manage their keys (`client.listApiKeys()`, `createApiKey({ name, scopes, expiresInDays, orgId? })`, `revokeApiKey(id)`). Self-service keys can only use `allowedScopes`. Creating one needs a recent sign-in, isn't allowed while impersonating, and for an organization needs `org:manage`. Your server can also create keys for any user or organization: `POST /v1/api_keys { name, scopes, userId | orgId }`.

A key looks like `ak_live_…`, is shown once, and only its hash is stored; the dashboard and API show the first characters (`prefix`), scopes, expiry, last used time and who it belongs to. Revoke with `DELETE /v1/api_keys/{id}`.

### Verify a key in your API

```ts
import { verifyApiKey } from "@daywalker/auth/server";
const r = await verifyApiKey(req.headers.get("x-api-key"), { secretKey, apiUrl, scopes: ["read:items"] });
if (!r.valid) return new Response("Unauthorized", { status: 401 });
// r.subject = { type: "user" | "org", id }
```

The check goes to the service, so revoked, expired and deleted keys, and keys of banned users, stop working immediately. It answers `{ valid: false }` without saying why.

## Audit and errors

Events: `m2m_client.created|updated|deleted|secret_rotated`, `user_api_key.created|revoked`. Error codes: `api_keys_disabled`, `scope_not_allowed`, `expiry_required`, `invalid_subject`, `limit_reached`.
