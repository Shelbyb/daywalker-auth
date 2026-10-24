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
{ "email": "ada@example.com", "password": "…", "firstName": "Ada", "lastName": "Lovelace", "legalAccepted": true }
```

`201` → `{ user, sessionId, jwt }` and sets the refresh cookie.
Errors: `email_taken` (409), `password_too_short` (400), validation (422).

## Sign in

```http
POST /v1/client/sign_in
{ "email": "ada@example.com", "password": "…" }
```

`200` → `{ status: "complete", user, sessionId, jwt }` and sets the refresh cookie, **or** `{ status: "needs_second_factor" }` with a 5-minute pending cookie (no session yet).
Errors: `invalid_credentials` (400, same for unknown email and wrong password), `forbidden` (403, banned), `rate_limited` (429).

## Second factor

```http
GET    /v1/client/organization_roles                         // roles to choose from
GET|POST /v1/client/organizations/{id}/domains              // org:manage
PATCH|DELETE /v1/client/organizations/{id}/domains/{domainId}
POST   /v1/client/organizations/{id}/domains/{domainId}/verify   // { method: "dns" } | { method: "email", mailbox | code }
GET    /v1/client/organizations/suggestions                 // organizations offered by verified email domain
POST   /v1/client/organizations/suggestions/{orgId}/accept
POST /v1/client/unlock                   { "token": "…" }   // one-time link from the "account locked" email
POST /v1/client/sign_in/second_factor   { "code": "123456" }   // or a backup code
```

Needs the pending cookie from `sign_in`. `200` → `{ status: "complete", user, sessionId, jwt }`. Five wrong codes void the attempt (`401`).

## Single sign-on

```http
POST /v1/client/sso/check  { "email" }   → { sso, connectionName, required }
GET  /v1/client/sso/start?pk=…&email=…&redirect_url=…   // navigate the browser here; it redirects to the company sign-in page
GET  /v1/client/environment              → { name, oauthProviders, passwordMinLength, legal, emailCodeSignIn, ssoEnabled, smsSecondFactor, ... }
```

When `required` is true, every other sign-in method for that address answers `403 sso_required`.

```http
DELETE /v1/client/session  { "redirectUrl"? } → { ok: true, ssoLogoutUrl? }
```

Signs out. `ssoLogoutUrl` is only there when the session came from an SSO connection with single logout on: send the browser there to sign out at the identity provider too. It comes back to `redirectUrl` (an allowed origin) or the hosted sign-in page.

## Two-factor setup (signed in)

```http
POST /v1/client/mfa/totp                  → { secret, uri }
POST /v1/client/mfa/totp/verify  { code } → { enabled: true, backupCodes: [...] }
POST /v1/client/mfa/totp/disable { code } → { enabled: false }
POST /v1/client/mfa/backup_codes { code } → { backupCodes: [...] }
```

Turning 2FA off, making new backup codes, and adding or removing any factor need a current code (authenticator, texted or backup), or a security key touch made earlier in the same session (see below).

### SMS

```http
POST /v1/client/mfa/sms          { phone, code? }  → { phone }      // texts a code; `code` needed if 2FA is already on
POST /v1/client/mfa/sms/verify   { code }          → { backupCodes }
POST /v1/client/mfa/sms/send                       → { phone }      // text a code to confirm a change
POST /v1/client/mfa/sms/remove   { code }          → { removed: true }
POST /v1/client/sign_in/second_factor/sms          // text a code during sign-in
```

Only numbers in the countries the instance allows can be added (`sms_country_not_allowed`).

### Security keys

```http
GET    /v1/client/mfa/security_keys                         → { securityKeys: [{ id, name, createdAt, lastUsedAt }] }
POST   /v1/client/mfa/security_keys/register/options { code? } → WebAuthn registration options
POST   /v1/client/mfa/security_keys/register/verify  { response, name? } → { id, backupCodes }
PATCH  /v1/client/mfa/security_keys/{id}            { name }
POST   /v1/client/mfa/security_keys/{id}/remove     { code? }
POST   /v1/client/sign_in/second_factor/security_key         → WebAuthn authentication options (needs the pending cookie)
POST   /v1/client/sign_in/second_factor             { response }  // the key's answer; or { code, method? }
```

Registering needs a sign-in from the last 15 minutes, and a current code if 2FA is already on. An account can hold 5 keys. A key is only ever a second factor; it can't sign anyone in alone.

**Confirming with a key instead of a code.** `POST /v1/client/mfa/security_keys/confirm/options` returns authentication options; `POST /v1/client/mfa/security_keys/confirm { response }` checks the answer and, for two minutes, lets that session make **one** sensitive change above by omitting `code`.

## Account (signed in)

```http
PATCH /v1/client/me                  { "firstName": "Grace", "lastName": null } → { user }
GET   /v1/client/me/security         → { hasPassword, twoFactorEnabled, totpEnabled, smsPhone, smsAvailable, securityKeys, backupCodesRemaining, connectedAccounts }
POST  /v1/client/password/change     { "currentPassword", "newPassword" } → { changed, otherSessionsSignedOut }
GET   /v1/client/sessions            → { sessions: [{ id, current, device, ipHint, lastActiveAt, createdAt }] }
POST  /v1/client/sessions/{id}/revoke
POST  /v1/client/sessions/revoke_others → { signedOut }
```

A session ID that isn't yours returns `404`, the same as one that doesn't exist, so IDs can't be probed.

## Passkeys

```http
POST   /v1/client/passkeys/register/options      → PublicKeyCredentialCreationOptions (needs a sign-in < 15 min old)
POST   /v1/client/passkeys/register/verify        { response, name? } → { id }
POST   /v1/client/passkeys/authenticate/options   → PublicKeyCredentialRequestOptions (no session needed)
POST   /v1/client/passkeys/authenticate/verify    { response } → { status: "complete", user, sessionId, jwt }
GET    /v1/client/passkeys                        → { passkeys: [...] }
PATCH  /v1/client/passkeys/{id}                   { name }
DELETE /v1/client/passkeys/{id}
```

`response` is the JSON-serialised `PublicKeyCredential` from the browser; the SDK produces it for you.

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

## Instance settings

```http
GET /v1/client/environment
```

`200` → `{ name, oauthProviders: ["google", "github"], passwordMinLength, legal: { required, termsUrl, privacyUrl, version } }`

## Social sign-in

```http
GET /v1/client/oauth/{google|github}/start?pk=pk_…&redirect_url=…&legal_accepted=1
```

Open this as a **full-page navigation**, not `fetch`. It redirects to the provider and sets a short-lived state cookie. The provider returns to `GET /v1/oauth/callback/{provider}`, which signs the user in and redirects to `redirect_url` (if allowed) or to the hosted page. Errors go to `/sign-in?error=<code>`; see [Social sign-in](/docs/guides/social-sign-in#errors-on-the-way-back).

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
| sign_in/second_factor | 30 / 15 min per IP, and 5 wrong codes per attempt |
| mfa/* | 10–20 / 15 min per IP |
| passkeys/authenticate/* | 60 options, 30 verifications / 5 min per IP |
| passkeys/register/options | 20 / 15 min per IP |

## Organizations

All need a signed-in session unless noted.

| Endpoint | Description |
| --- | --- |
| `GET` / `POST /v1/client/organizations` | List mine / create |
| `PATCH` / `DELETE /v1/client/organizations/{orgId}` | Rename / delete (admin) |
| `GET /v1/client/organizations/{orgId}/members` | List members |
| `PATCH` / `DELETE /v1/client/organizations/{orgId}/members/{userId}` | Change role / remove (`me` to leave) |
| `GET` / `POST /v1/client/organizations/{orgId}/invitations` | List / invite (admin) |
| `DELETE /v1/client/organizations/{orgId}/invitations/{id}` | Revoke (admin) |
| `POST /v1/client/invitations/preview` | Org name and role for a token (works signed out) |
| `POST /v1/client/invitations/accept` | Join with a token |
| `POST /v1/client/session/active_org` | Switch active organization; returns a new JWT |
