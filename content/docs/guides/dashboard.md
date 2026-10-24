---
title: The developer dashboard
description: Create instances, copy your keys, set allowed origins, turn on social sign-in and manage users from a web page instead of the command line.
---

The dashboard lives at `/dashboard` on your Daywalker Auth service (for example `https://users.daywalker.dev/dashboard`). Use it to set up and look after the apps that use your service.

## Vocabulary

- **Instance**: one app in one environment (for example "Acme, development" or "Acme, production"). Each instance has its own users, keys and settings, and nothing is shared between instances.
- **Publishable key** (`pk_…`): identifies your instance. It's safe to put in browser code.
- **Secret key** (`sk_…`): lets your server call the [backend API](/docs/api/backend). Keep it on the server only.

Open `/dashboard`, create your account, and you're in. Every person who signs up gets their own private account.

## What you can do

| Tab | What it's for |
| --- | --- |
| **Overview** | Your publishable key, the service URL and a ready-to-paste `.env.local` snippet |
| **API keys** | Create and revoke secret keys. A new key is shown **once**; we store only a hash |
| **Settings** | Name, allowed origins, minimum password length and how long sessions last |
| **SSO** | Enterprise SAML connections for your business customers |
| **Social sign-in** | Add Google, GitHub, Microsoft, Apple, Discord, GitLab or any OpenID Connect provider with your own credentials |
| **Terms** | Require new users to accept your terms of service |
| **Users** | See who signed up, suspend or restore accounts, delete users |
| **Webhooks** | Register endpoints, see delivery history, retry failures. See [Webhooks](/docs/guides/webhooks) |

### Allowed origins

List every website that will use this instance, one per line: for example `https://app.example.com` and `http://localhost:3000` while developing. Only these origins may sign users in and receive them after sign-in. Use the exact address, with no path and no `*`. Plain `http://` is only accepted for `localhost`.

### Revoking a key

Revoking is immediate: the key stops working on the very next request. Create the replacement first, update your server's environment, then revoke the old one, so there's no gap.

## Security notes

- You can only see and change instances that belong to your account. Anything else looks like it doesn't exist.
- Sensitive values (secret keys, signing secrets, OAuth client secrets) are shown once or never shown again. They are not stored in your browser.
- Deleting an instance permanently deletes its users, sessions, keys and webhooks. You must type the instance's name to confirm.
- Dashboard sessions work like any other: short-lived tokens, with the long-lived credential in an HttpOnly cookie.
