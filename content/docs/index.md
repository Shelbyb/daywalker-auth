---
title: Introduction
description: Add sign-up, sign-in and user management to your app without building auth yourself.
---

Daywalker Auth handles the parts of authentication that are easy to get wrong:

- storing passwords safely
- keeping people signed in
- proving to your server who is making a request
- recovering accounts

You add a few lines of code to your app; Daywalker Auth does the rest.

## What you get

- **Hosted sign-in and sign-up pages.** Send people there and they come back signed in. No forms to build.
- **Email verification and password reset**, with one-time codes sent by email.
- **Social sign-in** with Google, GitHub, Microsoft, Apple, Discord, GitLab or any OpenID Connect provider, with safe account linking.
- **Two-factor authentication** with authenticator apps and backup codes.
- **Passkeys**: passwordless sign-in with Face ID, fingerprints or a device PIN.
- **A hosted account page** where users manage their profile, password, 2FA and signed-in devices.
- **An SDK for Next.js and React** that tells any component or server route who the current user is.
- **Fast, private session checks.** Your server verifies each request locally in microseconds; it doesn't call us on every request.
- **A backend API** so your server can look up, update or remove users.
- **Encryption by default.** Emails, names and other personal data are encrypted before they're stored.

## Who these docs are for

You don't need to know how authentication works to use this. Each guide explains what's happening and why, then gives you code you can paste. If a term is unfamiliar, check the glossary below.

**New here?** Start with the [Quickstart](/docs/quickstart). It takes about 10 minutes and ends with a working, protected Next.js app.

## Glossary

| Term | Meaning |
|---|---|
| **Instance** | One app environment (e.g. "My App — development"). Users belong to exactly one instance. |
| **Publishable key** | `pk_test_…` / `pk_live_…`. Identifies your instance. Safe to put in browser code. |
| **Secret key** | `sk_test_…` / `sk_live_…`. Lets your server manage users. **Never** put it in browser code or commit it. |
| **Session** | A signed-in period on one device. Ends on sign-out, expiry or revocation. |
| **Session token** | A short-lived (60 second) signed JWT that proves who the user is. The SDK refreshes it automatically. |
| **JWKS** | The public keys used to check session tokens. Your server fetches them once and caches them. |
| **Frontend API** | Endpoints the browser calls (sign in, refresh token…). |
| **Backend API** | Endpoints your server calls with the secret key (list users, revoke sessions…). |

## How the pieces fit

```text
 Browser (your app)                Daywalker Auth                 Your server
 ──────────────────                ──────────────                 ───────────
 <AuthProvider> ──sign in──────▶   checks password
                ◀─session token──  issues 60s token
 fetch /api/orders ─────── Authorization: Bearer <token> ──────▶  verifyToken()
                                                                   ✓ userId = user_…
```

Read [How it works](/docs/how-it-works) for the full picture.
