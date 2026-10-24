---
title: Account lockout
description: Progressive lockout after repeated failed passwords or second-factor codes, with an emailed unlock link and admin unlock.
---

# Account lockout

Daywalker Auth locks an account for a while after too many wrong passwords or wrong second-factor codes. It is on for every instance and needs no code on your side.

## How it works

- **5 wrong answers in 15 minutes lock the account.** Wrong passwords and wrong two-factor codes (authenticator, SMS, backup code, security key) count together toward one lock. A correct answer forgives the failures for that step.
- **Locks grow each time:** 5 minutes, 15 minutes, 1 hour, 6 hours, then 24 hours. The count is forgotten 24 hours after a lock ends, or when you reset it (see below).
- **Attempts are reserved before the secret is checked,** so a flood of parallel guesses can't get past the limit.
- **While locked, even the right password is refused** with `429 account_locked`.
- **Same response whether or not the account exists.** An email address with no account is counted and locked exactly like a real one, so the response never tells an attacker which emails are registered. Only real accounts get an email, an audit entry and a webhook.
- **Privacy.** Counters and lock state in Valkey use HMAC-keyed names (no user IDs or emails in key names). Real accounts also have a row in `account_lockouts` (no personal data; the unlock token is stored only as a SHA-256), so a lock survives a Valkey restart.

Passkeys, social sign-in, SSO and email codes are not affected by a lock.

## Unlocking

1. **Emailed link.** When an account locks, its owner gets an email ("Account locked") with a single-use link, valid for 24 hours. The link opens a hosted page at `/unlock` and needs one click, so mail scanners can't use it up. Using the link keeps the escalation level, so a repeat attacker still gets longer locks.
2. **Password reset.** Completing a reset lifts the lock and resets the level.
3. **You, as the developer.** In the dashboard, open **Users**: locked accounts show a "locked until" badge and an **Unlock** button. From your backend:

```ts
const daywalker = createBackendClient({ secretKey: process.env.DAYWALKER_SECRET_KEY!, apiUrl: "https://users.daywalker.dev" });
const user = await daywalker.users.get(userId);   // user.lockedUntil: ISO time or null
await daywalker.users.unlock(userId);             // { id, unlocked: true | false }
```

Or `POST /v1/users/{userId}/unlock` with your secret key. An admin unlock also resets the level.

## Custom UI

Handle the `account_locked` error code (HTTP 429) on `signIn` and `completeSecondFactor`. If you build your own unlock page, read `#token=` from the URL fragment and call:

```ts
await auth.unlockAccount(token); // POST /v1/client/unlock; throws AuthError invalid_unlock_link if used or expired
```

The email wording is editable under **Emails** (`account_unlock`, with `{{link}}`, `{{app_name}}` and `{{expires_hours}}`).

## Events

| Where | Name | When |
| --- | --- | --- |
| Webhook + audit log | `user.locked` | An account locks. Data: `userId`, `lockedUntil`, `level`, `reason` (`password` or `second_factor`) |
| Webhook + audit log | `user.unlocked` | A lock is lifted. Data: `userId`, `reason` (`email_link`, `admin`, `password_reset`) |

Nothing is emitted for email addresses that have no account.

## Things to know

- Anyone who knows an email address can lock that account for a few minutes by guessing. That's the cost of any lockout; the unlock link and the short first lock keep it mild, and per-IP limits still apply.
- Failed attempts also still count toward the older per-IP and per-email request limits.
