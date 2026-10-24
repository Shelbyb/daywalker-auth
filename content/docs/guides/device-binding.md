---
title: Device-bound sessions
description: Tie each session to a key that never leaves the browser (DPoP, RFC 9449), so a stolen refresh cookie is useless on its own.
---

# Device-bound sessions

A refresh cookie is a bearer credential: whoever holds it is the user. With device binding the browser also holds a key it cannot export, and the service checks a short signed proof from that key every time the cookie is used. Malware, a leaked backup or a proxy log that captures the cookie gets nothing without the key.

This is DPoP ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)). The SDK does all of it; there is nothing to build.

## Turn it on

**Dashboard → Sessions → Device binding**, or the backend API:

```http
PATCH /v1/instance/device_binding     { "mode": "optional" }
GET   /v1/instance/device_binding     → { "mode": "optional" }
```

| Mode | Behavior |
|---|---|
| `off` (default) | Proofs are ignored. Nothing is bound. |
| `optional` | A session opened with a proof is bound. Sessions without one still work, so older SDKs and browsers without WebCrypto keep working. |
| `required` | Sign-in and sign-up without a proof are refused (`400 device_key_required`). Sessions that aren't bound stop working: switching to `required` signs out everyone who hasn't got a key, including sessions that exist now. |

A bound session stays bound even if you later switch to `off`.

## How it works

1. The SDK makes an ECDSA P-256 key with `extractable: false` and keeps it in IndexedDB. Script on the page can use the key to sign but can never read it.
2. On every request to the frontend API it adds a `DPoP` header: a JWT signed by that key naming the HTTP method and URL, with a random `jti` and the time.
3. When a session is created, the thumbprint of the key (RFC 7638) is stored with it. From then on every use of the cookie (token refresh, reading the session, account changes, switching organization) must carry a proof from the same key. A missing or different key gives `401 device_proof_required` or `401 invalid_dpop_proof`.
4. The session token (JWT) of a bound session carries `cnf: { "jkt": "…" }`. `verifyToken` returns it as `deviceKey`.

The service accepts only `ES256` with a public P-256 key in the header, `typ: dpop+jwt`, `htm` and `htu` matching the request (the URL without query), `iat` within 60 seconds, and a `jti` it has not seen in the last two minutes (kept in Valkey). There is no server-issued nonce; replay is bounded by `iat` and `jti`.

Signing out needs only the cookie, so a browser that lost its key can still end the session.

## Sign-ins that return through a redirect

Social sign-in, SSO and the link in an email come back as a browser redirect, which cannot carry a proof. Those sessions start unbound; in `required` mode they may do nothing except be bound for the first two minutes. The SDK's `load()` sees that the session is unbound and calls:

```http
POST /v1/client/session/bind        (with a DPoP header)
→ { "sessionId": "…", "deviceBound": true }
```

It works once per session, only within two minutes of sign-in, and never replaces an existing key (`409 already_bound`, `403 bind_window_closed`). Until then the cookie is unbound, so this window is the one place where a cookie stolen in the first seconds could win the race. Everything after it is bound.

## In the SDK

```ts
const client = createAuthClient({ publishableKey, frontendApi });   // nothing else to configure
```

The key is made the first time a session is about to open and the app asks for binding. `createAuthClient` takes `deviceKeyStore` to keep keys somewhere other than IndexedDB (tests, non-browser runtimes). `createDpopProof`, `generateDeviceKey` and `deviceKeysSupported` are exported from `@daywalker/auth`.

`authProxy`'s refresh page uses the same key, so server-rendered pages keep refreshing.

`GET /v1/client/session` returns `deviceBound`, `deviceBindable` and `deviceBinding`; the environment endpoint returns `sessions.deviceBinding`.

## Requirements and limits

- `frontendApi` must be the service's own origin (`APP_URL`): the proof names the URL it was sent to.
- Clearing site data deletes the key. The user is signed out and signs in again.
- Platform support impersonation sessions are not bound.
- The key stops a stolen *cookie*. Malicious script running in your own page can still ask the browser to sign requests while the page is open; keep your CSP strict.

Audit events: `session.device_bound`, `instance.sessions_updated` (with `deviceBinding`); `user.signed_in` records `deviceBound`.
