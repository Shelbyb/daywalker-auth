---
title: "@daywalker/auth (browser)"
description: The framework-agnostic browser client used by the React package.
---

Use this directly with Vue, Svelte, vanilla JS or anything else that runs in a browser.

```ts
import { createAuthClient } from "@daywalker/auth";

const auth = createAuthClient({
  publishableKey: "pk_test_…",
  frontendApi: "https://users.daywalker.dev",
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
| `disableTwoFactor(code?)` / `regenerateBackupCodes(code?)` | Manage 2FA; both need a current code, or call `confirmWithSecurityKey()` first and pass none |
| `startSmsSetup(phone, code?)` / `confirmSmsSetup(code)` / `removeSmsPhone(code?)` | SMS as a second factor (when the app allows it) |
| `addSecurityKey({ name?, currentCode? })` / `listSecurityKeys()` / `renameSecurityKey(id, name)` / `removeSecurityKey(id, code?)` | Security keys (YubiKey and similar) as a second factor |
| `completeSecondFactorWithSecurityKey()` | Finishes a 2FA sign-in by touching a key |
| `confirmWithSecurityKey()` | Confirms one sensitive change (add/remove a factor, turn 2FA off, new backup codes) with a key instead of a code, for two minutes |
| `signUp({ email, password, firstName?, lastName? })` | Creates the account and signs in |
| `setOrganizationTwoFactor(orgId, required)` | Admins: require two-step verification for an organization's members |
| `signOut({ redirectUrl?, singleLogout? })` | Ends the session here and in other tabs. For a company SSO sign-in with single logout on, then goes via the identity provider to `redirectUrl`. Resolves `{ redirecting }` |
| `getToken({ force? })` | A valid session token, or `null` |
| `authFetch(url, init)` | `fetch` plus `Authorization: Bearer <token>` |
| `sendVerificationCode()` / `verifyEmail(code)` | [Email verification](/docs/guides/email-verification) |
| `requestPasswordReset(email)` / `resetPassword({ email, code, password })` | [Password reset](/docs/guides/password-reset) |
| `signInWithOAuth(provider, redirectUrl?)` | Redirect to a social provider (`google`, `github`, `microsoft`, `apple`, `discord`, `gitlab`, `oidc`); returns signed in. See [Social sign-in](/docs/guides/social-sign-in). |
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

## Organizations

| Method | Notes |
| --- | --- |
| `listOrganizations()` | Orgs you belong to, with your role |
| `createOrganization(name)` | You become admin |
| `renameOrganization(orgId, name)` / `deleteOrganization(orgId)` | Admins only |
| `listOrgMembers(orgId)` | Any member |
| `changeOrgRole(orgId, userId, "admin" \| "member")` | Admins only; the last admin can't be demoted |
| `removeOrgMember(orgId, userId)` | Admins remove others; pass your own ID (or `"me"`) to leave |
| `inviteToOrg(orgId, email, role?)` / `listOrgInvitations(orgId)` / `revokeOrgInvitation(orgId, id)` | Admins only |
| `previewInvitation(token)` / `acceptInvitation(token)` | The hosted `/accept-invite` page uses these |
| `setActiveOrganization(orgId \| null)` | Refreshes the JWT so `org_id` / `org_role` update |

See the [Organizations guide](/docs/guides/organizations).
