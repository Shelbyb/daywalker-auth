---
title: Sign-up protection
description: Keep bots and throwaway accounts out with email rules and a human check.
---

# Sign-up protection

Three switches, all off by default. Turn them on in the dashboard (**Settings → Sign-up protection and two-factor**) or from your backend.

## Email rules

- **Only allow these domains.** For an internal tool, list `mycompany.com` and nobody else can create an account. Subdomains count (`eu.mycompany.com`), look-alikes don't (`notmycompany.com`).
- **Block these domains.** For example a domain you've seen abuse from.
- **Block throwaway addresses.** Refuses about 120,000 known disposable email providers, such as mailinator.com.

The rules apply to **new accounts**, from email sign-up and social sign-in. People who already have an account keep signing in normally. Company SSO and SCIM aren't affected, because the company vouches for those people. A refused sign-up gets one generic message (`403 sign_up_not_allowed`), so someone probing can't learn the rules.

## Human check (Cloudflare Turnstile)

[Turnstile](https://developers.cloudflare.com/turnstile/) is a free, privacy-friendly CAPTCHA alternative. Most people never see a puzzle.

1. In Cloudflare, create a Turnstile widget for your domains. You get a **site key** and a **secret key**.
2. Paste both into the dashboard. The secret is stored encrypted and never shown again.

From then on, **sign-up** and **emailing a sign-in code** need a fresh Turnstile answer. The hosted pages and the drop-in `<SignUp />` / `<SignIn />` components show the widget for you. In your own form, read the site key from `getEnvironment().captcha`, render the widget, and pass its token:

```ts
await client.signUp({ email, password, captchaToken });
await client.sendSignInCode({ email, captchaToken });
```

Each answer works once. Password sign-in, passkeys and social sign-in don't need it (they already have their own rate limits and checks).

If Turnstile can't be reached, the request is refused rather than let through. If you use the components in your own app with a strict Content Security Policy, allow `https://challenges.cloudflare.com` in `script-src` and `frame-src`.

## From your backend

```bash
curl -X PATCH https://users.daywalker.dev/v1/instance/protection \
  -H "Authorization: Bearer $DAYWALKER_SECRET_KEY" -H "content-type: application/json" \
  -d '{ "allowedDomains": [], "blockedDomains": ["spam.example"], "blockDisposableEmails": true,
        "captcha": { "siteKey": "0x4AAAA…", "secretKey": "0x4AAAA…" } }'
```

`GET /v1/instance/protection` returns the current settings (never the secret). `"captcha": null` turns the human check off. The same endpoint sets the [two-factor requirement](/docs/guides/two-factor#requiring-2fa).
