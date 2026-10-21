---
title: "@daywalker/auth (browser)"
description: The framework-agnostic browser client used by the React package.
---

Use this directly with Vue, Svelte, vanilla JS or anything else that runs in a browser.

```ts
import { createAuthClient } from "@daywalker/auth";

const auth = createAuthClient({
  publishableKey: "pk_test_…",
  frontendApi: "https://auth.daywalker.dev",
});

await auth.load(); // find out if someone is signed in
auth.subscribe((state) => render(state)); // { isLoaded, user, sessionId }
```

## Methods

| Method | Description |
|---|---|
| `load()` | Fetches the current session. Call once on startup. |
| `subscribe(fn)` | Calls `fn` on every state change. Returns an unsubscribe function. |
| `state` | Current `{ isLoaded, user, sessionId }` |
| `signIn({ email, password })` | Signs in; resolves with the user |
| `signUp({ email, password, firstName?, lastName? })` | Creates the account and signs in |
| `signOut()` | Ends the session here and in other tabs |
| `getToken({ force? })` | A valid session token, or `null` |
| `authFetch(url, init)` | `fetch` plus `Authorization: Bearer <token>` |
| `sendVerificationCode()` / `verifyEmail(code)` | [Email verification](/docs/guides/email-verification) |
| `requestPasswordReset(email)` / `resetPassword({ email, code, password })` | [Password reset](/docs/guides/password-reset) |
| `signInWithOAuth(provider, redirectUrl?)` | Redirect to Google or GitHub; returns signed in. See [Social sign-in](/docs/guides/social-sign-in). |
| `getEnvironment()` | `{ name, oauthProviders, passwordMinLength }`, for building your own sign-in UI |
| `hostedUrl(page, redirectUrl?)` | URL of `"sign-in"`, `"sign-up"` or `"forgot-password"` |

## Options

| Option | Default | Description |
|---|---|---|
| `publishableKey` | required | Your `pk_…` key |
| `frontendApi` | required | URL of the auth service |
| `syncCookie` | `true` | Mirror the token into the `__dw_session` cookie so your server can read it on page loads |

## Where things are stored

| What | Where | Readable by JS? |
|---|---|---|
| Refresh token | `HttpOnly` cookie on the auth domain | No |
| Session token | Memory, plus the `__dw_session` cookie on your domain (60 s) | Yes, by design. It's short-lived. |
| "Was signed in" flag | `__dw_active` cookie on your domain | Yes. Contains no secret. |

Nothing is ever written to `localStorage` or `sessionStorage`.
