---
title: Satellite domains
description: Run one app on several domains and keep people signed in across them, with a secure redirect handshake and no third-party cookies.
---

# Satellite domains

Your app might live on more than one domain: `example.com` and `example.org`, or a product on its own domain. With satellite domains everyone signed in on one is recognised on the others.

- The **primary domain** is your main site. Set it under **Dashboard → Configure → Domains**, or `PUT /v1/instance/primary_domain { "primaryDomain": "https://example.com" }`. It is added to your allowed origins automatically.
- A **satellite domain** is any other domain of the same app. You prove you control it with a DNS record, and from then on it is an allowed origin too (CORS, the CSRF check and redirect targets) and can sync sessions.

Browsers increasingly block third-party cookies, so a satellite can't just read the auth service's cookie. Instead it asks for the session with a redirect.

## Add a satellite

```ts
const sat = await backend.satelliteDomains.add("example.org");
// sat.dns → { type: "TXT", name: "_daywalker.example.org", value: "daywalker-verify=…" }
await backend.satelliteDomains.verify(sat.id);   // 400 verification_failed until the record is published
```

Domains must use https. On a **development** instance `http://localhost:3002` is accepted without a DNS record. A verified origin belongs to one app only (`domain_taken` otherwise). Up to 10 satellites. The records are checked once, when you verify.

## Configure the satellite app

```bash
NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY=pk_…       # the same instance as the primary
NEXT_PUBLIC_DAYWALKER_AUTH_URL=https://auth.example.com
NEXT_PUBLIC_DAYWALKER_IS_SATELLITE=true
NEXT_PUBLIC_DAYWALKER_PRIMARY_DOMAIN=https://example.com
NEXT_PUBLIC_DAYWALKER_DOMAIN=https://example.org     # only if the request origin differs (behind a proxy)
DAYWALKER_AUTHORIZED_PARTIES=https://example.com,https://example.org
```

Or in code: `authProxy({ protect: [...], config: { publishableKey, frontendApi, isSatellite: true, primaryDomain } })` and `<AuthProvider isSatellite primaryDomain="https://example.com">`. `isSatellite` without `primaryDomain` throws at startup.

`authProxy` serves two paths on the satellite for you: `/__daywalker/sync` and `/__daywalker/handshake`. A protected page without a session first tries a silent sync, and only then sends the person to sign in (and back through the sync afterwards). To recognise signed-in visitors on public pages too, add `syncPaths: ["/"]`.

## How the handshake works

1. The satellite makes a random **verifier**, keeps it in an httpOnly cookie, and redirects the browser to `GET /v1/client/satellite/sync` with `challenge = base64url(sha256(verifier))`.
2. The service reads its own cookie (first-party there). If there is a session it creates a **one-time code** (60 seconds, stored encrypted with a token minted for that satellite, `azp` = its origin) and redirects to the satellite's fixed `/__daywalker/handshake` path with only the code. No session: `status=signed_out`.
3. The satellite's server posts `{ code, verifier }` to `POST /v1/client/satellite/exchange` and gets the short-lived token, which it stores in the usual `__dw_session` cookie.

A code in a URL, log or history is useless without the verifier, works once, and dies if the satellite is removed. The service redirects only to verified satellites, never to the primary domain or an arbitrary `return` URL, and the `to` target is accepted only if it is on the satellite itself. A misconfiguration ends in an error page after 4 tries a minute instead of a redirect loop.

## Good to know

- Tokens last 60 seconds; the satellite re-syncs by redirect when one expires, so a sign-out on the primary reaches satellites within a minute.
- Device-bound sessions ([device binding](/docs/guides/device-binding)), impersonated sessions and sessions that still owe two-factor setup are not shared: the satellite sees them as signed out.
- In the browser, a satellite without third-party cookies learns the signed-in session from the synced cookie (`useAuth` works, `useUser` has no profile). Server code (`auth()`, `authProxy`) always works.
- Sign-in itself still happens on the hosted pages; a satellite is a valid `redirect_url`.

Errors: `invalid_satellite`, `primary_mismatch`, `invalid_challenge`, `invalid_code`, `invalid_domain`, `domain_not_allowed`, `domain_exists`, `domain_taken`, `domain_is_primary`, `domain_is_satellite`, `verification_failed`.
