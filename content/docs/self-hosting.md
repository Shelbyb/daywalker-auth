---
title: Self-hosting
description: Run Daywalker Auth on your own infrastructure.
---

## Requirements

- Node.js 22+
- PostgreSQL 16+
- Valkey 8+ (or any Redis-protocol server)

## Local development

```bash
cp .env.example .env
# put the output of this into MASTER_KEY:
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"

docker compose up -d     # Postgres + Valkey
npm install
npm run db:migrate
npm run seed -- http://localhost:3001
npm run dev              # http://localhost:3000, docs at /docs
```

In development, emails aren't sent; they're printed in the server console.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | yes | Postgres URL. In production, include `?sslmode=verify-full`. |
| `VALKEY_URL` | yes | `redis://…` locally, `rediss://…` (TLS) in production |
| `MASTER_KEY` | yes | 32 random bytes, base64. Encrypts everything sensitive. |
| `APP_URL` | yes | Public URL of this service. Becomes part of token issuers, so don't change it casually. |
| `MAIL_TRANSPORT` | prod | `resend` in production, `dev` locally |
| `RESEND_API_KEY` | prod | API key for sending email through Resend |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_VERIFY_SERVICE_SID` | no | Twilio Verify, for [SMS two-factor](/docs/guides/two-factor#text-message-codes-sms). Set all three or none. |
| `PASSKEY_RP_ID` | no | Domain passkeys are bound to. Default: the hostname of `APP_URL`. Set to a parent domain (e.g. `example.com`) to use passkeys on app subdomains. Decide before launch. |
| `OAUTH_TEST_BASE_URL` | tests only | Points Google/GitHub at a mock provider. Refused when `APP_URL` is HTTPS. |
| `MAIL_FROM` | no | Sender, e.g. `Acme <no-reply@auth.acme.com>` (domain must be verified with Resend) |

## Production checklist

1. Generate `MASTER_KEY` in a secrets manager and back it up securely. **Without it, encrypted data is lost.**
2. Use managed Postgres with TLS, and restrict network access to the service.
3. Use Valkey with TLS and a password or ACL user.
4. Put the service behind a load balancer that terminates HTTPS and sets `X-Forwarded-For`.
5. Run `npm run db:migrate` on each deploy, before starting the new version.
6. Verify your sending domain in Resend (SPF/DKIM) so codes don't land in spam.
7. Serve it from a subdomain of your apps (e.g. `users.example.com`), so its cookies count as first-party.

## Scaling

- The service is stateless; run as many copies as you like.
- Postgres stores the durable data. Valkey holds caches, rate limits and short-lived codes, so losing it signs nobody out; it just costs a few extra database reads.
