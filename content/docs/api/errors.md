---
title: Errors
description: Every error has the same shape, with a machine-readable code and a human-readable message.
---

```json
{
  "error": {
    "code": "invalid_credentials",
    "message": "Email or password is incorrect"
  }
}
```

Validation errors (422) also include the fields that failed:

```json
{
  "error": {
    "code": "invalid_request",
    "message": "Invalid request",
    "fields": [{ "path": "email", "message": "Invalid email address" }]
  }
}
```

In the SDK these become `AuthError` (browser) or `BackendError` (server), with `status`, `code`, `message` and, for `AuthError`, `fields`.

- **Branch on `code`**, never on `message`; messages may be reworded.
- **`message` is safe to show to end users.**

## Codes

| Code | Status | Meaning | What to do |
|---|---|---|---|
| `invalid_request` | 422 | Body failed validation | Show `fields` next to the inputs |
| `invalid_credentials` | 400 | Wrong email or password | Ask the user to try again |
| `password_too_short` | 400 | Below the minimum length | Ask for a longer password |
| `email_taken` | 409 | Email already registered in this instance | Offer sign-in or reset |
| `invalid_code` | 400 | Verification/reset code wrong, expired, used, or out of guesses | Offer "send a new code" |
| `email_unverified` | 400 | Social account has no verified email | Verify it with the provider, or use email sign-in |
| `provider_disabled` | 400 | That social provider isn't enabled | Enable it via the backend API |
| `oauth_cancelled` / `oauth_failed` | — | Social sign-in cancelled or failed (in the `error` query param) | Let the user try again |
| `already_enabled` | 409 | 2FA is already on | Nothing to do, or disable it first |
| `no_pending_enrollment` | 400 | Confirmed 2FA without starting setup | Call `startTotpSetup()` first |
| `not_enabled` | 400 | 2FA action on an account without 2FA | |
| `no_password` | 400 | Password change on an account that signs in with Google/GitHub only | Use password reset to set one |
| `current_session` | 400 | Tried to revoke the current session through the devices list | Use sign out instead |
| `already_verified` | 400 | Email is already verified | Nothing to do |
| `unauthenticated` | 401 | No valid session or key | Sign in, or check your keys |
| `forbidden` | 403 | Origin not allowed, or account suspended | Add the origin, or contact support |
| `not_found` | 404 | No such user/session in this instance | |
| `rate_limited` | 429 | Too many attempts | Wait and retry |
| `internal_error` | 500 | Unexpected failure (details only in server logs) | Retry; report if it persists |
