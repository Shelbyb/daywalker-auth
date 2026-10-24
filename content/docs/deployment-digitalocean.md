---
title: Deploy on DigitalOcean
description: Step-by-step guide to running Daywalker Auth on DigitalOcean App Platform with managed Postgres and Valkey.
---

This guide takes you from nothing to a running auth service at `users.daywalker.dev`. You need a DigitalOcean account, a GitHub repository containing this project, and a domain managed in DigitalOcean (the examples use `daywalker.dev`; swap in your own).

## What you will create

- A **managed Postgres** database (durable data: users, sessions, keys).
- A **managed Valkey** database (caches, rate limits, short-lived codes).
- An **App Platform app** with a web service built from the `Dockerfile`, plus a job that runs migrations before every deploy.

## 1. Create the databases

1. In the DigitalOcean console choose **Create > Databases**, pick **PostgreSQL 16**, and create it in the same region as your app.
2. Create a second database, **Valkey 8**, in the same region.
3. Under each database's **Trusted sources**, add your app once it exists. Nothing else should be allowed.

If you use the app spec in step 3, it can also create small dev databases for you. Use separate managed clusters for production.

## 2. Generate your secrets

```bash
# MASTER_KEY: 48 random bytes, base64. Encrypts signing keys at rest.
openssl rand -base64 48
```

Store `MASTER_KEY` in a password manager. **If you lose it, encrypted data cannot be recovered**, and changing it locks everyone out. Create a [Resend](https://resend.com) API key too and verify your sending domain (SPF and DKIM).

## 3. Create the app

Copy `.do/app.yaml`, replace `Shelbyb/<repo>` and `<yourdomain>`, then:

```bash
doctl apps create --spec .do/app.yaml
```

Or use **Create > App**, pick your repo, and choose the Dockerfile. In the app's settings set these variables:

| Variable | Value |
|---|---|
| `APP_URL` | `https://users.daywalker.dev` |
| `DATABASE_URL` | `${db.DATABASE_URL}` |
| `DATABASE_CA_CERT` | `${db.CA_CERT}` (verifies the Postgres certificate) |
| `VALKEY_URL` | `${cache.DATABASE_URL}` (must start with `rediss://`) |
| `MASTER_KEY` | your generated key, as an **encrypted/secret** variable |
| `MAIL_TRANSPORT` | `resend` |
| `RESEND_API_KEY` | secret |
| `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_VERIFY_SERVICE_SID` | optional, secrets; only for SMS two-factor |
| `MAIL_FROM` | `Acme <no-reply@users.daywalker.dev>` |
| `PASSKEY_RP_ID` | `<yourdomain>` |
| `TRUST_PROXY_HOPS` | `1` |

> **Warning**: Never put real secrets in `.do/app.yaml` or Git. Leave placeholders and enter values in the dashboard.

## 4. Migrations

The spec defines a `PRE_DEPLOY` job that runs `node migrate.mjs` in the same image before each new version starts. It applies the SQL files in `drizzle/`. If it fails, the deploy stops and the old version keeps serving.

## 5. Custom domain

Add `users.daywalker.dev` under **Settings > Domains**, and pick your domain. If the domain's DNS is managed in DigitalOcean, the record is created for you; otherwise add the CNAME it shows you. HTTPS certificates are issued automatically. Serving auth from a subdomain of your apps keeps its cookies first-party.

## 6. Health checks

`GET /healthz` returns `{"ok":true}` and is used by App Platform. `GET /healthz?deep=1` also checks Postgres and Valkey and returns `503 {"ok":false}` on failure, with no details. Use the deep check for external uptime monitors, not for the platform health check, so a Valkey blip does not restart healthy containers.

## 7. Passkeys

`PASSKEY_RP_ID` is the domain passkeys are bound to. Set it to your parent domain (for example `example.com`) so apps on other subdomains can use them. Decide before launch: changing it later invalidates every registered passkey.

## Client IPs and rate limits

Rate limits key on the client IP. App Platform appends the real client address to `X-Forwarded-For`. The service reads the Nth entry from the **right**, where N is `TRUST_PROXY_HOPS` (default `1` in production), so a client cannot fake its address by sending its own header. If you add another proxy (such as a CDN) in front, increase the value by one. Set `0` to ignore forwarding headers entirely.

## Scaling

- The service is stateless: raise `instance_count` or enable autoscaling on a Professional plan.
- Start with `basic-xxs` only for testing; password hashing is CPU and memory heavy, so use at least `basic-xs` in production.
- Scale Postgres vertically first, and add a standby node for failover. Valkey loss is harmless.
- Each instance opens up to 10 Postgres connections. Keep `instances x 10` under your plan's connection limit, or use a connection pool.

## Security checklist

1. `MASTER_KEY`, `RESEND_API_KEY` and database passwords are secrets only, backed up and never committed.
2. Postgres and Valkey trusted sources list only your app.
3. `DATABASE_CA_CERT` is set and `VALKEY_URL` starts with `rediss://`.
4. `APP_URL` is `https://` and matches your custom domain.
5. Resend domain is verified and `MAIL_TRANSPORT=resend`.
6. `TRUST_PROXY_HOPS` matches the number of proxies in front of the app.
7. Automated database backups are on.
8. `PASSKEY_RP_ID` is final.

## Webhook delivery

Webhooks are delivered by a small loop inside the web service itself, so there is nothing extra to deploy. With several instances running, each delivery is claimed by exactly one of them. Set `WEBHOOK_WORKER=0` on an instance to turn the loop off there. Never set `WEBHOOK_ALLOW_PRIVATE` in production: it lets webhooks call internal addresses and only exists for local testing.

## The developer dashboard

After the first successful deploy, open a console on the web service (or run it locally against the production database) and create the platform instance:

```bash
npm run bootstrap:platform
```

Copy the `PLATFORM_PUBLISHABLE_KEY=pk_live_…` line it prints into the app's environment variables (it isn't secret, but keep it with your other settings) and redeploy. Then `https://users.daywalker.dev/dashboard` works. Run the command only once. See [the dashboard guide](/docs/guides/dashboard).
