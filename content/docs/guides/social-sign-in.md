---
title: Social sign-in
description: Let people sign in with Google, GitHub, Microsoft, Apple, Discord, GitLab or any OpenID Connect provider.
---

Social sign-in lets someone click **Continue with Google** instead of making up yet another password. Daywalker supports **Google, GitHub, Microsoft, Apple, Discord, GitLab** (including self-hosted) and **any OpenID Connect provider** (Okta, Auth0, Keycloak, Zitadel and others). Behind the scenes it uses OAuth 2.0 and OpenID Connect:

1. Your user is sent to the provider.
2. They approve.
3. They're sent back to Daywalker Auth with a one-time code.
4. Daywalker Auth exchanges that code for their profile, signs them in, and returns them to your app.

Setting up a provider takes about five minutes.

## 1. Create an OAuth app with the provider

Each provider needs to know your app exists and where to send people back. That address is your **callback URL**:

```text
https://<your auth domain>/v1/oauth/callback/<provider>
```

`<provider>` is one of `google`, `github`, `microsoft`, `apple`, `discord`, `gitlab` or `oidc`. The dashboard shows the exact URL for each one under **Social sign-in**.

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

### Microsoft

1. In the **Microsoft Entra admin center**, go to **App registrations → New registration**.
2. Choose who can sign in. "Accounts in any organizational directory and personal Microsoft accounts" works for most apps.
3. Add a **Web** redirect URI: your Microsoft callback URL.
4. Under **Certificates & secrets**, create a client secret. Copy it and the **Application (client) ID**.
5. Optional but recommended: under **Token configuration**, add the optional claim **`xms_edov`** to the ID token (see "Why Microsoft is stricter" below).

Settings: `tenant` (optional). Leave it empty to allow any Microsoft account, or use your tenant ID to allow only your organization.

### Apple

1. In **Apple Developer → Certificates, IDs & Profiles**, create an **App ID** with Sign in with Apple enabled.
2. Create a **Services ID**. This is your client ID. Turn on Sign in with Apple, and add your domain and Apple callback URL.
3. Under **Keys**, create a key with Sign in with Apple, and download the `.p8` file. Note the **Key ID** and your **Team ID**.
4. Give Daywalker the Services ID as the client ID, the whole `.p8` file as the client secret, and `teamId` and `keyId` as settings.

Apple doesn't have a static client secret. Daywalker signs a fresh, 5-minute one with your key for each sign-in, and your key stays encrypted. Apple shares the user's name only the first time they sign in, and users may choose a private relay email address.

### Discord

1. Open the **Discord Developer Portal → Applications → New Application → OAuth2**.
2. Add your Discord callback URL as a redirect, and copy the **Client ID** and **Client secret**.

### GitLab

1. In GitLab, go to **Preferences → Applications** (or the group or instance admin area) and add an application.
2. Use your GitLab callback URL, tick **Confidential**, and choose the scopes `openid`, `email` and `profile`.
3. Copy the **Application ID** and **Secret**.

Settings: `issuer` (optional). Leave it empty for gitlab.com, or use your self-hosted URL such as `https://gitlab.example.com`.

### Any OpenID Connect provider

1. Create a "web" or "confidential" application in your identity provider, with your `oidc` callback URL and the scopes `openid`, `email` and `profile`.
2. Find its **issuer URL**, for example `https://acme.okta.com` or `https://auth.example.com/realms/main`. Daywalker reads everything else from `<issuer>/.well-known/openid-configuration`.

Settings: `issuer` (required) and `displayName` (the button says "Continue with *displayName*").

> **Tip** Create separate OAuth apps for development and production. Each one only allows its own callback URL, so you can't accidentally mix them up.

## 2. Give the credentials to Daywalker Auth

Call the backend API with your **secret key**:

```bash
curl -X PUT https://users.example.com/v1/instance/oauth/google \
  -H "Authorization: Bearer $DAYWALKER_SECRET_KEY" \
  -H "content-type: application/json" \
  -d '{ "clientId": "1234.apps.googleusercontent.com", "clientSecret": "GOCSPX-…" }'
```

```json
{ "provider": "google", "enabled": true, "clientId": "1234.apps.googleusercontent.com",
  "redirectUri": "https://users.example.com/v1/oauth/callback/google" }
```

Providers with extra options take a `settings` object:

```bash
curl -X PUT https://users.example.com/v1/instance/oauth/oidc \
  -H "Authorization: Bearer $DAYWALKER_SECRET_KEY" -H "content-type: application/json" \
  -d '{ "clientId": "…", "clientSecret": "…", "settings": { "issuer": "https://acme.okta.com", "displayName": "Acme SSO" } }'
```

| Provider | `settings` |
|---|---|
| `microsoft` | `{ "tenant": "common" }` (optional) |
| `apple` | `{ "teamId": "ABCDE12345", "keyId": "XYZ9876543" }` (required). The client secret is the `.p8` file |
| `gitlab` | `{ "issuer": "https://gitlab.example.com" }` (optional) |
| `oidc` | `{ "issuer": "https://…", "displayName": "Acme SSO" }` (issuer required) |

You can also do all of this in the dashboard under **Social sign-in**.

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

> **Note** Providers publish branding rules and official button artwork for "Sign in with…" buttons. The SDK's buttons are unstyled text, so add the official assets if you want the logos.

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

### What counts as verified

| Provider | Trusted email |
|---|---|
| Google, GitLab, OpenID Connect | `email_verified` is true |
| GitHub | The **primary, verified** address from the user's email settings (the public profile email is ignored) |
| Discord | The account's email is marked `verified` |
| Apple | `email_verified` in Apple's signed ID token |
| Microsoft | Personal Microsoft accounts, or work accounts whose token carries `xms_edov: true` |

### Why Microsoft is stricter

In Microsoft work and school accounts, an organization's admin can set a user's email to **any** address, including one at a domain they don't own. Accepting that email blindly would let someone create a tenant, set a user's email to `ceo@yourcustomer.com`, and sign in as that person. This is the well-known "nOAuth" problem.

So Daywalker only trusts a Microsoft email when it's a personal account, or when Microsoft says the domain is verified (the `xms_edov` claim). Otherwise sign-in is refused with `email_unverified`, unless that Microsoft account was linked to a user before.

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
- **Signed ID tokens.** For Microsoft, Apple and OpenID Connect, the ID token's signature, issuer, audience, expiry and a one-time **nonce** are all checked. Provider signing keys are cached and refetched when a provider rotates them.
- **Pinned issuers.** An OpenID Connect discovery document must name the exact issuer you configured, or sign-in is refused.
- **No requests to private networks.** Issuer, token, user-info and key URLs must be public `https` addresses. Requests to internal or cloud-metadata addresses are blocked, redirects aren't followed, and responses are size-limited.
- **No plaintext identifiers.** Provider user IDs are stored as keyed hashes, and emails are encrypted.
