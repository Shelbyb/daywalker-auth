---
title: Step-up authentication
description: Ask for a fresh password, passkey or second factor before a sensitive action, with a server check and a ready-made prompt.
---

# Step-up authentication

A session can be days old. Before something that matters (changing a payout account, exporting data, deleting a project) you often want proof the person is *still there*. Step-up authentication does that without signing them out: your server says "prove yourself in the last 5 minutes", the browser asks, and the request is retried.

## What the token says

Every session remembers when its person last proved a **first factor** (password, passkey, emailed code, or the identity provider at sign-in) and a **second factor** (authenticator app, text message, security key, backup code). Session tokens carry both:

| Claim | Meaning |
|---|---|
| `auth_time` | When the first factor was last proved (seconds since epoch, as in OpenID Connect) |
| `fva` | `[first, second]`: seconds since each factor was proved when the token was issued, `-1` if it never was in this session |

A user-verified passkey (device plus biometric or PIN) counts as both factors. Signing in with a password and then a 2FA code proves both. A token refresh never makes anything fresher; only proving a factor again does.

`auth_time` and `fva` are reserved: custom claims can't use those names.

## On your server

```ts
import { auth, ReverificationRequiredError } from "@daywalker/auth/nextjs";

export async function POST() {
  const session = await auth();
  if (!session.isSignedIn) return Response.json({ error: "unauthenticated" }, { status: 401 });
  try {
    session.requireRecentAuth({ maxAge: 300, level: "multi_factor" });   // seconds
  } catch (e) {
    if (e instanceof ReverificationRequiredError) return e.toResponse();   // 403 reverification_required
    throw e;
  }
  // …do the sensitive thing
}
```

Without Next.js, use the functions from `@daywalker/auth/server`:

```ts
import { verifyToken, requireRecentAuth, isRecentlyVerified, reverificationResponse } from "@daywalker/auth/server";

const claims = await verifyToken(bearer, config);
if (!isRecentlyVerified(claims, { maxAge: 300, level: "second_factor" })) return reverificationResponse({ maxAge: 300, level: "second_factor" });
```

| `level` | Satisfied when |
|---|---|
| `first_factor` (default) | the password, a passkey or an emailed code was proved within `maxAge` |
| `second_factor` | an authenticator, text, security key or backup code (or a passkey) was proved within `maxAge` |
| `multi_factor` | both were |

Ages are measured when you check: the age in the token plus the time since it was issued, so an old token cannot look fresh. A request with no valid token, an invalid `maxAge`, or an account that has no second factor never passes `second_factor`/`multi_factor`; the prompt then tells the person to set up two-step verification.

Decide on the server. The token is signed, so this check can't be forged from the browser.

## In the browser

`<AuthProvider>` mounts the prompt for you. `authFetch` (from `useAuth()` or the client) sees the 403 `reverification_required`, opens it, and retries the request once with a fresh token:

```tsx
const { authFetch } = useAuth();
const res = await authFetch("/api/payouts", { method: "POST", body: JSON.stringify(payload) });
```

The prompt offers only what the account has: a passkey, the password or an emailed code for the first factor; a passkey, security key, authenticator/text/backup code for the second factor. Escape or Cancel resolves false and `authFetch` returns the 403. Request bodies that are streams can't be replayed, so they are not retried.

Customize or replace it:

```tsx
<AuthProvider reverificationPrompt={false}>…</AuthProvider>   // register your own below

const { requestReverification } = useAuth();
const ok = await requestReverification({ level: "first_factor", maxAge: 300 });
```

`<ReverificationPrompt need={{ level, maxAge }} onDone={(ok) => …} />` is exported for custom placement and takes the same `appearance.classNames` as the other components (`modalBackdrop` is the extra part).

For a fully custom UI, `client.setReverificationHandler(fn)` plus the calls it makes:

| Method | Proves |
|---|---|
| `getReverificationOptions()` | what this account can use: `{ password, passkey, totp, sms, securityKey, backupCodes, emailCode }` |
| `reverifyWithPassword(password)` | first factor |
| `reverifyWithPasskey()` | both factors |
| `reverifyWithCode(code, method?)` | second factor (authenticator, text or backup code) |
| `reverifyWithSecurityKey()` | second factor |
| `sendReverificationEmailCode()` then `reverifyWithEmailCode(code)` | first factor, for accounts with no password and no two-factor |

Each stores the fresh token, so the next `getToken()` already carries the new ages.

## API

```http
GET  /v1/client/session/reverify                  → { password, passkey, totp, sms, securityKey, backupCodes, emailCode }
POST /v1/client/session/reverify                  { "factor": "password", "password": "…" }
                                                  { "factor": "code", "code": "123456", "method": "totp" }   // or a backup code
                                                  { "factor": "email_code", "code": "123456" }
                                                  { "factor": "security_key" }                       // after mfa/security_keys/confirm
                                                  → { "verified": true, "jwt": "…" }
POST /v1/client/session/reverify/passkey/options  → WebAuthn options (only this person's passkeys)
POST /v1/client/session/reverify/passkey          { "response": { … } } → { "verified": true, "jwt": "…" }
```

Wrong passwords and codes count toward [account lockout](/docs/guides/account-lockout) exactly like sign-in, and each proof is audited as `user.reverified` (with the method, never the secret). Not available to a platform operator impersonating the user (`403 impersonation_forbidden`). Rate limited to 30 attempts per 15 minutes.

If the sensitive endpoint is on the auth service itself, nothing changes: password changes, 2FA changes and deletion already ask for the current password or code in the same request.
