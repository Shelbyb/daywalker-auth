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
| 2FA secrets | AES-256-GCM per user |
| Backup codes | Keyed HMAC; marked used atomically |
| Passkeys | Public keys only; private keys never leave the user's device |
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
| Stolen password | Optional TOTP 2FA, also enforced after social sign-in |
| Replayed 2FA code | Each accepted 30-second window can only be used once |
| Phishing | Passkeys only work on your real domain |
| Adding a backdoor passkey from a hijacked session | Registration needs a session started in the last 15 minutes |
| Stealing a session to weaken two-factor | Turning 2FA off, adding or removing a factor, and new backup codes need a current code or a security key touch (valid 2 minutes, once, for that session only) |
| Skipping company sign-in | With "SSO required", password, email code, magic link, passkey, social sign-in and password reset are refused for those domains, and switching it on signs out everyone already in |
| A leaked or over-broad provisioning token | The SCIM token is random, only its SHA-256 is stored, it works for one connection's own domains and people only, and the last admin of an organization is never demoted by a group push |
| Forged or replayed SSO logout | Logout messages must be signed by the IdP's certificate (unsigned redirect messages are refused), match its issuer and our URL, be recent, and work once; a logout answer can only send the browser to a redirect we stored |
| Cloned security key | Signature counters must always increase |
| Code guessing | 6 digits, 5 guesses, 10 minutes, single use |
| Stolen database dump | Personal data encrypted; passwords hashed; tokens hashed |
| Leaked logs or cache | Rate-limit keys are HMAC'd; no raw IPs or emails in Valkey |

## Your responsibilities

- **Keep `MASTER_KEY` and secret keys in a secrets manager.** Losing the master key makes stored personal data unrecoverable; leaking it exposes it.
- **Check authorization** in your own code (scope queries by `userId`).
- **Run behind a proxy that sets `X-Forwarded-For`** correctly; IP rate limits depend on it.
- **Keep the allowed-origins list short**, with only domains you control.

## Webhooks

Outgoing webhooks are signed with a per-endpoint secret (HMAC-SHA256, with a timestamp to stop replays). Endpoint URLs, secrets and queued payloads are encrypted at rest. We only call public `https://` addresses: private ranges, loopback and cloud metadata addresses are refused, the address is checked again at connection time, and redirects are not followed. See [Webhooks](/docs/guides/webhooks).
