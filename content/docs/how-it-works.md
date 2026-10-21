---
title: How it works
description: Sessions, tokens and keys, explained without jargon.
---

You don't need this page to get started, but it makes everything else easier to reason about, especially when debugging.

## The two tokens

When someone signs in, they get two things.

**1. A refresh token: the long-lived one.**
- Lives in a cookie on the Daywalker Auth domain, marked `HttpOnly`, so no JavaScript (yours or an attacker's) can read it.
- Lasts for the session (7 days by default).
- Its only job is to get a new session token.

**2. A session token: the short-lived one.**
- A signed [JWT](https://jwt.io/introduction) that says "this is user `user_abc`, session `sess_xyz`".
- Expires after **60 seconds**.
- The SDK fetches a new one about 10 seconds before the old one expires, as long as the tab is open.

Why two? A short-lived token can be checked very quickly without a database. Keeping it short-lived means that if a user signs out or is banned, every token for them stops working within a minute.

## What happens on a request

```text
1. Browser: SDK has a fresh session token in memory
2. Browser → your server: request with the token
      - as Authorization: Bearer <token>   (from authFetch)
      - or as the __dw_session cookie      (page loads, set by the SDK)
3. Your server: verifyToken()/auth() checks
      - the signature, using your instance's public keys (fetched once, cached)
      - that it isn't expired
      - that it was issued by your instance
4. Your server: knows userId, runs your code
```

Step 3 involves **no network call** after the first one. That's why checking auth on every request is cheap.

## Returning after being away

Say a user closes the tab and comes back an hour later. Their 60-second token has long expired, but their refresh token is still valid.

1. `authProxy` sees the expired token plus a small `__dw_active` flag cookie meaning "this person was signed in".
2. Instead of redirecting to sign-in, it serves a tiny page that asks Daywalker Auth for a new token using the refresh cookie.
3. The page reloads, now with a valid token. The user only sees a brief flash.

If the session has ended, the refresh fails and the user goes to sign-in as normal.

## Keys

| Key | Where it goes | What it can do |
|---|---|---|
| Publishable `pk_…` | Browser code, env vars with `NEXT_PUBLIC_` | Identify your instance to the Frontend API. Nothing else. |
| Secret `sk_…` | Server env only | Read, change and delete your users; revoke sessions. |

The publishable key is like a username for your app: public by design. The secret key is like a password: anyone who has it controls your users.

## Instances

An instance is one isolated set of users and settings. Users, sessions and signing keys never cross instances. Most teams use one instance per environment, such as development and production, so test accounts never mix with real ones.
