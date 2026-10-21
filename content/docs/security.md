---
title: Security model
description: What's protected, how, and what's still your responsibility.
---

## Data at rest

| Data | Stored as |
|---|---|
| Passwords | **argon2id** hash (19 MiB memory, 2 iterations). Never stored or logged in plain text. |
| Emails, names, private metadata, session IP and browser | **AES-256-GCM** ciphertext, bound to its table, column and row |
| Email lookups | Keyed HMAC "blind index", scoped per instance |
| Refresh tokens, secret keys | SHA-256 hash only. They're 256-bit random values, so this is irreversible. |
| Verification and reset codes | Keyed HMAC in Valkey, deleted after 10 minutes, on use, or after 5 wrong guesses |
| OAuth client secrets | AES-256-GCM, bound to instance and provider; never returned by any API |
| Social account IDs | Keyed HMAC only |
| JWT signing keys | Private key AES-256-GCM encrypted; decrypted only into server memory |

**The key hierarchy.**
- A single `MASTER_KEY` (32 random bytes) is the root.
- It never encrypts data directly; separate keys for encryption and indexing are derived from it with HKDF.
- Each ciphertext records its key version (`v1.`), so the master key can be rotated later.

**Why bind ciphertext to its row?** If someone with database access copied an encrypted email from one row into another, decryption would fail rather than reveal data in the wrong place.

## Data in transit

- In production the service **refuses to start** unless:
  - `APP_URL` is HTTPS
  - Postgres uses `sslmode=require` or stricter
  - Valkey uses `rediss://` (TLS)
- Pages send `Strict-Transport-Security` with preload.

## Sessions

- **Refresh token:** `HttpOnly`, `Secure`, scoped to `/v1/client`. Page scripts can never read it.
- **Session token:** lives 60 seconds, so sign-out, revocation, bans, deletions and password resets take effect everywhere within a minute.
- **Password reset** revokes every session.

## Attacks and defences

| Attack | Defence |
|---|---|
| Password guessing | Per-IP and per-account rate limits; argon2 makes offline cracking slow |
| Finding out who has an account | Same error and same timing for unknown emails; forgot-password always says "sent" |
| Cross-site request forgery | Frontend API only accepts mutations from allowed origins |
| Phishing via redirects | `redirect_url` must be a relative path or an allowed origin |
| Clickjacking | `frame-ancestors 'none'` and `X-Frame-Options: DENY` |
| Forged or tampered tokens | ES256 signatures checked; `alg` pinned; issuer and expiry checked |
| Token from another app | Optional `authorizedParties` check on `azp` |
| Social login CSRF or replay | `state` bound to an HttpOnly cookie and single-use server record, plus PKCE |
| Pre-registering someone's email | Verified social sign-in removes the password and sessions from never-verified accounts |
| Code guessing | 6 digits, 5 guesses, 10 minutes, single use |
| Stolen database dump | Personal data encrypted; passwords hashed; tokens hashed |
| Leaked logs or cache | Rate-limit keys are HMAC'd; no raw IPs or emails in Valkey |

## Your responsibilities

- **Keep `MASTER_KEY` and secret keys in a secrets manager.** Losing the master key makes stored personal data unrecoverable; leaking it exposes it.
- **Check authorization** in your own code (scope queries by `userId`).
- **Run behind a proxy that sets `X-Forwarded-For`** correctly; IP rate limits depend on it.
- **Keep the allowed-origins list short**, with only domains you control.
