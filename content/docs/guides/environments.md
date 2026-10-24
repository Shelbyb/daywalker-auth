---
title: Development and production
description: Separate development and production instances per application, with their own keys, and copy configuration from one to the other without copying users.
---

# Development and production

An **application** has up to two instances: a **development** instance for building and a **production** instance for real users. They share nothing at runtime: separate users, sessions, publishable keys (`pk_test_…` / `pk_live_…`), secret keys (`sk_test_…` / `sk_live_…`), signing keys and JWKS. A token from development never verifies against production.

Create the production instance in **Dashboard → Configure → Developers → Environments** on the development instance.

## Development banner

The `<SignIn/>` and `<SignUp/>` components (and the hosted pages) show a "Development mode" banner when the instance is a development one, so nobody mistakes it for the real thing. It can't be turned off through `appearance`. The environment endpoint reports it as `instanceEnvironment`.

## Copy configuration to production

On the production instance, **Environments → Copy configuration from development**, or call the backend API **with the production secret key**:

```http
POST /v1/instance/clone
{ "include": { "settings": true, "providers": true, "templates": true, "roles": true, "webhooks": false, "origins": false },
  "copySecrets": [] }
```

The production key is used on purpose: a leaked development key can't overwrite production.

| Part | What is copied |
|---|---|
| `settings` | Sign-in options, sessions, organizations, sign-up rules, branding, legal. Not `redirects`, the Turnstile site key or `requireTwoFactor` (reported under `skipped`). |
| `providers` | Provider type, client ID and options. Created **disabled** with no secret, unless the secret is copied. Existing production providers are left alone. |
| `templates` | Email templates. |
| `roles` | Organization roles, merged by key. |
| `webhooks` (off by default) | Endpoints with a fresh signing secret (returned once), created **disabled**. |
| `origins` (off by default) | Allowed origins, never `localhost`. |

Never copied: users, sessions, API keys, signing keys, SSO connections, domains, audit log.

**Secrets** (`"copySecrets": ["providers", "webhooks"]`) are copied only if you list them. They are decrypted and encrypted again for the production instance; the ciphertext is bound to its instance, so nothing is copied as-is.

The response lists `copied`, `skipped` (with reasons) and `webhookSecrets`. The action is audited as `instance.config_cloned`.

## SDK

```ts
const prod = createBackendClient({ secretKey: process.env.PROD_SECRET_KEY!, apiUrl });
await prod.environments.get();                        // this instance and its siblings
await prod.environments.cloneFromDevelopment({ include: { webhooks: true } });
```

Errors: `clone_target_not_production`, `no_development_instance`, `secrets_without_part`, `environment_exists`, `provider_needs_secret`.
