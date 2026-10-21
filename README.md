# Daywalker Auth

Multi-tenant authentication service: email/password sign-in, sessions, short-lived ES256 JWTs, and a backend API. Next.js 16 + Tailwind 4, PostgreSQL (Drizzle), Valkey.

```
src/               the auth service (APIs + hosted sign-in/sign-up pages)
packages/sdk/      @daywalker/auth — SDK for apps (browser, React, server, Next.js)  → see its README
examples/nextjs/   a Next.js app protected with the SDK
```

**Integrating an app? Start with the [SDK README](packages/sdk/README.md).** The raw HTTP APIs below are what the SDK calls.

## Run locally

```bash
cp .env.example .env            # then set MASTER_KEY (command in the file)
docker compose up -d            # Postgres 16 + Valkey 8
npm install
npm run db:migrate
npm run seed -- http://localhost:5173   # optional: origins of your app allowed to call the frontend API
npm run dev
```

Seeding prints a publishable key (public) and a secret key (shown once). Hosted pages: `/sign-in?pk=<publishable key>` and `/sign-up?pk=...`.

Run the example app against it:

```bash
npm run seed -- http://localhost:3001     # copy the keys into examples/nextjs/.env.local (see .env.example there)
cd examples/nextjs && npm run dev         # http://localhost:3001
```

Tests (servers running): `npm run test:e2e` (28 service checks: auth flows, encryption at rest, CSRF, revocation, rate limits, headers) and `npm run test:sdk` (19 SDK checks: token verification incl. forged/`alg:none`/foreign-app tokens, route protection, refresh, open-redirect defenses).

## APIs

| Surface | Auth | Routes |
|---|---|---|
| Frontend API (browsers) | `x-publishable-key` + refresh cookie | `POST /v1/client/sign_up`, `POST /v1/client/sign_in`, `POST /v1/client/session/token`, `GET`/`DELETE /v1/client/session` |
| Backend API (your servers) | `Authorization: Bearer sk_...` | `GET /v1/users`, `GET`/`DELETE /v1/users/:id`, `POST /v1/sessions/:id/revoke` |
| Token verification | public | `/i/:instanceId/.well-known/jwks.json`, `/.well-known/openid-configuration` |

Your app verifies session JWTs locally against the JWKS (issuer `APP_URL/i/<instanceId>`); no network call per request.

## Security model

**Encryption at rest**
- `MASTER_KEY` never encrypts data directly; HKDF derives separate subkeys for encryption and indexing.
- PII (emails, names, private metadata, session IP and user agent) is AES-256-GCM encrypted per field, with the table, column and row ID bound as AAD so ciphertexts can't be moved between rows.
- Emails are looked up through a keyed HMAC blind index, scoped per instance.
- JWT signing private keys are encrypted in Postgres and decrypted only into process memory, never into Valkey.

**Secrets that are never stored**
- Passwords: argon2id (19 MiB, t=2).
- Refresh tokens and secret keys: only SHA-256 hashes (both are 256-bit random values).

**Sessions**
- The refresh token lives in an HttpOnly, Secure, path-scoped cookie; JS never sees it.
- JWTs live 60 s, so revocation and bans take effect within a minute.
- Session state is cached in Valkey and purged on sign-out, revoke and user delete.

**Request hardening**
- The frontend API rejects mutations from origins that aren't this service or the instance's allow-list (CSRF), and grants CORS only to those origins.
- The backend API sends no CORS headers.
- Sign-in has per-IP and per-account rate limits. Valkey keys are HMAC'd, so raw IPs and emails never land in the cache.
- Sign-in runs an argon2 verify even for unknown emails and returns one generic error, so it doesn't reveal which accounts exist.
- Redirects after sign-in are validated server-side: relative paths, or origins on the instance's allow-list. Anything else is dropped, so the hosted pages can't be used as an open redirect.
- Pages send a strict CSP with `frame-ancestors 'none'` and HSTS in production; API responses are `no-store`.

**Transport**
- In production, startup refuses non-HTTPS `APP_URL`, Postgres without `sslmode=require|verify-full`, and Valkey without `rediss://`.

## Next.js performance
- Pages are server components; JS ships only for interactive islands (the auth form, the SDK's auth-aware widgets).
- `loading.tsx` boundaries stream a skeleton instantly; slow data (e.g. backend profile fetches in the example dashboard) sits behind `<Suspense>` so the shell streams first.
- Session checks in `auth()`/`authProxy` verify JWTs locally (JWKS cached), so protected routes add no network hop.
- Navigation uses `next/link` (viewport prefetch); user avatars use `next/image` with an explicit `remotePatterns` allow-list.
- System font stack: zero font downloads. To use a web font, add `next/font` (self-hosted at build time, so it fits the CSP).

## Production checklist
- Generate `MASTER_KEY` in a secrets manager (KMS / Secrets Manager); never commit it. Losing it makes PII unrecoverable.
- Enable Valkey AUTH/ACLs and TLS; restrict Postgres to the app's network.
- Put the service behind a proxy that sets a trustworthy `X-Forwarded-For` (rate limits key on it).
- Rotate signing keys periodically: create a new key, mark the old one inactive, and keep it in the JWKS until outstanding tokens expire.

## Not built yet
Email verification and OTP/magic links, password reset, OAuth, passkeys, TOTP MFA, organizations, webhooks, dashboard, prebuilt embeddable sign-in component, CSP nonce for the SDK refresh page, signing-key rotation endpoint, MASTER_KEY rotation (ciphertexts are versioned `v1.` to allow it), and breached-password checks.
