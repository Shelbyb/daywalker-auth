---
title: Sign in with Google and GitHub
description: Let people sign in with an account they already have.
---

Social sign-in lets someone click **Continue with Google** instead of making up yet another password. Behind the scenes it uses OAuth 2.0:

1. Your user is sent to Google or GitHub.
2. They approve.
3. They're sent back to Daywalker Auth with a one-time code.
4. Daywalker Auth exchanges that code for their profile, signs them in, and returns them to your app.

Setting up a provider takes about five minutes.

## 1. Create an OAuth app with the provider

Each provider needs to know your app exists and where to send people back. That address is your **callback URL**:

```text
https://<your auth domain>/v1/oauth/callback/google
https://<your auth domain>/v1/oauth/callback/github
```

Locally that's `http://localhost:3000/v1/oauth/callback/google`.

### Google

1. Open the Google Cloud Console and create (or pick) a project.
2. Go to **APIs & Services → OAuth consent screen**. Fill in your app name and support email, and add the scopes `openid`, `email` and `profile`.
3. Go to **APIs & Services → Credentials → Create credentials → OAuth client ID**.
4. Choose **Web application**. Under **Authorized redirect URIs**, add your Google callback URL exactly.
5. Copy the **Client ID** and **Client secret**.

### GitHub

1. Go to **GitHub → Settings → Developer settings → OAuth Apps → New OAuth App**. For an organization, use the organization's settings instead.
2. Set **Homepage URL** to your app and **Authorization callback URL** to your GitHub callback URL.
3. Create the app, then **Generate a new client secret**.
4. Copy the **Client ID** and **Client secret**.

> **Tip** Create separate OAuth apps for development and production. Each one only allows its own callback URL, so you can't accidentally mix them up.

## 2. Give the credentials to Daywalker Auth

Call the backend API with your **secret key**:

```bash
curl -X PUT https://auth.example.com/v1/instance/oauth/google \
  -H "Authorization: Bearer $DAYWALKER_SECRET_KEY" \
  -H "content-type: application/json" \
  -d '{ "clientId": "1234.apps.googleusercontent.com", "clientSecret": "GOCSPX-…" }'
```

```json
{ "provider": "google", "enabled": true, "clientId": "1234.apps.googleusercontent.com",
  "redirectUri": "https://auth.example.com/v1/oauth/callback/google" }
```

- The client secret is **encrypted** before it's stored, and is never returned by any API.
- To switch a provider off without deleting it, send `"enabled": false`.

## 3. Add the buttons

**Hosted pages:** nothing to do. Once a provider is enabled, its button appears on the sign-in and sign-up pages.

**Your own UI** uses `<OAuthButton>`:

```tsx
"use client";
import { OAuthButton } from "@daywalker/auth/react";

export function SocialButtons() {
  return (
    <div className="grid gap-2">
      <OAuthButton provider="google" className="btn" />
      <OAuthButton provider="github" className="btn">Sign in with GitHub</OAuthButton>
    </div>
  );
}
```

Or call it from any handler:

```ts
const { signInWithOAuth } = useAuth();
signInWithOAuth("github", "https://app.example.com/dashboard"); // full-page redirect
```

The user comes back to the URL you pass, or the current page if you don't pass one. That URL must be on your instance's **allowed origins**; anything else is ignored.

> **Note** Google and GitHub each publish branding rules and official button artwork for "Sign in with…" buttons. The SDK's buttons are unstyled text, so add the official assets if you want the logos.

## How accounts are matched

When someone signs in with a provider:

| Situation | Result |
|---|---|
| They've used this provider account before | Signed into the same user |
| New provider account, its **verified** email matches an existing user | Linked to that user; they can now use either method |
| New provider account, no matching email | A new user is created, with the email already marked verified |
| The provider doesn't report a verified email | Sign-in is refused (`email_unverified`) |

### Why only verified emails?

Imagine someone signs up on your app with `ceo@yourcustomer.com` and a password, without ever verifying it. Later the real CEO clicks **Continue with Google**. If we simply linked the accounts, the impostor's password would still work.

So when a provider proves ownership of an email whose account was **never verified**, Daywalker Auth:

- removes that account's password, and
- signs out all of its sessions.

The real owner keeps the account; the impostor loses access.

For GitHub, only the **primary, verified** address from the user's email settings counts. The public profile email is ignored.

## Errors on the way back

If something goes wrong, the user lands on the sign-in page with a clear message:

| Code | When |
|---|---|
| `oauth_cancelled` | The user clicked **Cancel** at the provider |
| `email_unverified` | The provider account has no verified email |
| `provider_disabled` | The provider isn't enabled for this instance |
| `forbidden` | The matching account is suspended |
| `oauth_failed` | Anything else, such as an expired attempt or a provider outage |

## Security details

- **State, bound to the browser.** Each attempt gets a random `state`, stored server-side (encrypted, 10 minutes, single use) **and** in an `HttpOnly` cookie. The callback only proceeds if both match. This stops "login CSRF", where an attacker tricks you into finishing *their* sign-in so your activity lands in their account.
- **PKCE.** A one-time secret proves the code is exchanged by whoever started the flow, even if the code leaks.
- **Exact callback URL.** Providers only redirect to the callback URL you registered.
- **No plaintext identifiers.** Provider user IDs are stored as keyed hashes, and emails are encrypted.
