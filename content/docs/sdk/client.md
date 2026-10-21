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
| `signIn({ email, password })` | Resolves `{ status: "complete", user }` or `{ status: "needs_second_factor" }` |
| `completeSecondFactor(code)` | Finishes a 2FA sign-in with an authenticator or backup code |
| `startTotpSetup()` / `confirmTotpSetup(code)` | Turn on 2FA; confirm returns backup codes |
| `disableTwoFactor(code)` / `regenerateBackupCodes(code)` | Manage 2FA; both need a current code |
| `signUp({ email, password, firstName?, lastName? })` | Creates the account and signs in |
| `signOut()` | Ends the session here and in other tabs |
| `getToken({ force? })` | A valid session token, or `null` |
| `authFetch(url, init)` | `fetch` plus `Authorization: Bearer <token>` |
| `sendVerificationCode()` / `verifyEmail(code)` | [Email verification](/docs/guides/email-verification) |
| `requestPasswordReset(email)` / `resetPassword({ email, code, password })` | [Password reset](/docs/guides/password-reset) |
| `signInWithOAuth(provider, redirectUrl?)` | Redirect to Google or GitHub; returns signed in. See [Social sign-in](/docs/guides/social-sign-in). |
| `getEnvironment()` | `{ name, oauthProviders, passwordMinLength }`, for building your own sign-in UI |
| `updateProfile({ firstName?, lastName? })` | Edit the user's name (`null` clears a field) |
| `changePassword({ currentPassword, newPassword })` | Signs out all other sessions |
| `getSecurity()` | `{ hasPassword, twoFactorEnabled, backupCodesRemaining, connectedAccounts }` |
| `listSessions()` / `revokeSession(id)` / `revokeOtherSessions()` | Manage signed-in devices |
| `passkeysSupported()` / `signInWithPasskey()` | Detect support; usernameless passkey sign-in. See [Passkeys](/docs/guides/passkeys). |
| `registerPasskey(name?)` / `listPasskeys()` / `renamePasskey(id, name)` / `deletePasskey(id)` | Manage passkeys |
| `hostedUrl(page, redirectUrl?)` | URL of `"sign-in"`, `"sign-up"`, `"forgot-password"` or `"account"` |

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
