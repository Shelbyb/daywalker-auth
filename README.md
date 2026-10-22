# Daywalker Auth

Multi-tenant authentication service for apps: email/password, social sign-in, passkeys, two-factor, organizations, webhooks and a developer dashboard. Next.js 16 + Tailwind 4, PostgreSQL (Drizzle), Valkey. Runs at `users.daywalker.dev`.

**Full documentation lives in the app at `/docs`** (also in [`content/docs`](content/docs)). Start with the quickstart.

```
src/               the service: APIs, hosted pages (sign-in, account, accept-invite), /dashboard, /docs
packages/sdk/      @daywalker/auth: SDK for apps (browser, React, server, Next.js). See its README
examples/nextjs/   a Next.js app protected with the SDK
content/docs/      the documentation (Markdown)
scripts/           seed, migrate, bootstrap-platform and the end-to-end test suites
```

## What's included

| Area | Highlights |
|---|---|
| Sign-in | Email + password (argon2id, breached passwords blocked via k-anonymity), email verification, password reset, passwordless email codes and magic links, Google, GitHub, Microsoft, Apple, Discord, GitLab and any OpenID Connect provider, passkeys (WebAuthn), TOTP two-factor with backup codes |
| Sessions | HttpOnly refresh cookie + 60-second ES256 JWTs verified locally against per-instance JWKS; revoke and ban take effect within a minute |
| Accounts | Hosted account page (profile, password, sessions, passkeys, two-factor) |
| Organizations | Roles (admin/member), invitations by email, active organization with `org_id`/`org_role` in the JWT |
| Enterprise SSO | SAML 2.0 connections per customer, routed by email domain, JIT organization membership, signed-assertion checks with replay and wrapping protection |
| Webhooks | HMAC-signed (Standard Webhooks format), retries with backoff, delivery log, SSRF protection |
| Audit logs | Sign-ins, failed attempts, security, key and settings changes; encrypted details; 90-day retention; dashboard and API |
| Terms | Optional required terms acceptance at sign-up, recorded per user and version |
| Emails | Per-instance wording for every email, brand color, preview and test sends; plain text with escaped placeholders |
| Dashboard | `/dashboard`: instances, keys, allowed origins, social providers, terms, users, emails, webhooks, audit log |
| SDK | Browser client, React hooks, drop-in `<SignIn />` / `<SignUp />` / `<UserButton />` / `<OrganizationSwitcher />`, server `verifyToken`/`verifyWebhook`/backend client, Next.js `auth()` and `authProxy` |

## Run locally

```bash
cp .env.example .env            # then set MASTER_KEY (command in the file)
docker compose up -d            # Postgres 16 + Valkey 8
npm install
npm run db:migrate
npm run seed -- http://localhost:3001   # origins of your app allowed to call the frontend API
npm run dev
```

Seeding prints a publishable key (public) and a secret key (shown once). Hosted pages: `/sign-in?pk=<publishable key>` and `/sign-up?pk=...`.

To use the dashboard locally, run `npm run bootstrap:platform` once and put the printed `PLATFORM_PUBLISHABLE_KEY` in `.env`, then open `/dashboard`.

Run the example app against it:

```bash
npm run seed -- http://localhost:3001     # copy the keys into examples/nextjs/.env.local (see .env.example there)
cd examples/nextjs && npm run dev         # http://localhost:3001
```

## Tests

Build and start the service (`npm run build`, then `next start` with `ALLOW_INSECURE_TRANSPORT=1 WEBHOOK_ALLOW_PRIVATE=1 OAUTH_TEST_BASE_URL=http://localhost:3999`) and run:

```bash
npm run test:all     # service, recovery, OAuth, two-factor, account, passkeys, terms, organizations, webhooks, dashboard
npm run test:sdk     # needs examples/nextjs running on :3001 with its keys in the environment
```

About 330 checks in total, covering auth flows, encryption at rest, CSRF, revocation, rate limits, tenant isolation, SSRF rules and security headers. CI runs the same suites (see `.github/workflows/ci.yml`).

## Deploying

See [`content/docs/deployment-digitalocean.md`](content/docs/deployment-digitalocean.md): a `Dockerfile` and `.do/app.yaml` for DigitalOcean App Platform with managed Postgres and Valkey, a pre-deploy migration job, and `/healthz`.

## APIs

| Surface | Auth | Routes |
|---|---|---|
| Frontend API (browsers) | `x-publishable-key` + refresh cookie | `/v1/client/*`: sign-up, sign-in, session, email, password, mfa, passkeys, organizations, invitations |
| Backend API (your servers) | `Authorization: Bearer sk_...` | `/v1/users`, `/v1/sessions`, `/v1/organizations`, `/v1/webhooks`, `/v1/instance/*` |
| Token verification | public | `/i/:instanceId/.well-known/jwks.json`, `/.well-known/openid-configuration` |

Full reference: `/docs/api/frontend` and `/docs/api/backend`. Your app verifies session JWTs locally against the JWKS (issuer `APP_URL/i/<instanceId>`); there's no network call per request.

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
- Hosted pages and the dashboard send a per-request nonce CSP with `frame-ancestors 'none'`; API responses get `default-src 'none'`, are `no-store`, and HSTS is on in production.
- Webhook URLs must be public HTTPS addresses (private ranges and metadata addresses are refused and re-checked at connect time); endpoint URLs, secrets and payloads are encrypted at rest.
- The dashboard re-checks account ownership on every action and shows secrets once.

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
- Put the service behind a proxy that sets a trustworthy `X-Forwarded-For` and set `TRUST_PROXY_HOPS` to the number of proxies (rate limits key on it).
- Rotate signing keys periodically from the dashboard (old keys stay in the JWKS for 24 hours), and rotate `MASTER_KEY` if it may have leaked. See [Rotating keys](content/docs/guides/rotating-keys.md).

## Next steps

Working notes and current status: [`NEXT_STEPS.md`](NEXT_STEPS.md).

Done: signing-key rotation, `MASTER_KEY` rotation, audit logs, magic links and email codes, the breached-password check, custom email templates, more social providers, drop-in React components, and enterprise SSO (SAML). Planned, in this order (details and status in [`content/docs/roadmap.md`](content/docs/roadmap.md)):

1. SMS codes (needs an SMS provider choice)
