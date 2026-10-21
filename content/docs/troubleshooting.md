---
title: Troubleshooting
description: Common problems and how to fix them.
---

## "Origin not allowed" (403)

Your app's URL isn't on the instance's allowed origins. Add the **exact** origin: scheme, host and port, no path (e.g. `http://localhost:3001`, `https://app.example.com`).

## Signed in, but the server says I'm signed out

- **Is `AuthProvider` mounted?** The `__dw_session` cookie is only written once it has loaded.
- **Is the API on another domain?** Cookies don't cross domains; use [`authFetch`](/docs/guides/call-your-api).
- **Do the keys match?** `NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY` must be from the same instance the user signed into.
- **Is `DAYWALKER_AUTHORIZED_PARTIES` set?** It must include the origin your frontend runs on.

## "Invalid publishable key"

The key is malformed or from a deleted instance. Copy it again, including the `pk_test_` prefix. In Next.js, restart the dev server after editing `.env.local`.

## Signed out after every page reload in production

Browsers block third-party cookies. If your app is on `app.example.com` and the auth service is on a completely different domain, the refresh cookie counts as third-party. Host the service on a subdomain of the same site (e.g. `auth.example.com`).

## A flash of a blank page when I come back

That's `authProxy` refreshing an expired token (see [How it works](/docs/how-it-works#returning-after-being-away)). It takes one round trip.

If your app sets a strict Content-Security-Policy, that refresh page's inline script may be blocked. Allow it, or remove the route from `protect` and handle signed-out users in the page itself.

## Codes never arrive

- **Locally:** codes are printed in the auth service's console (`[mail:dev]`).
- **In production:** check that `MAIL_TRANSPORT=resend`, the API key is valid, and the sending domain is verified. Also check spam folders.

## `verifyToken` throws instead of returning null

It throws when it can't download the public keys. Check that your server can reach `<auth url>/i/<instance>/.well-known/jwks.json`.
