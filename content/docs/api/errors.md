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
| `legal_required` | 400 | Terms must be accepted to create an account | Show the checkbox; pass `legalAccepted: true` |
| `reauth_required` | 403 | Adding a passkey needs a sign-in from the last 15 minutes | Sign in again, then retry |
| `passkey_invalid` | 400 | Passkey couldn't be verified (any reason) | Try again or use another sign-in method |
| `challenge_expired` | 400 | Passkey setup took longer than 5 minutes | Start again |
| `passkey_exists` | 409 | This device already has a passkey for the account | Nothing to do |
| `too_many_passkeys` | 400 | Already 10 passkeys | Remove one first |
| `passkey_cancelled` / `passkey_unsupported` | — | Browser prompt closed, or no passkey support (SDK only) | Hide passkey options or let the user retry |
| `sso_required` | 403 | The email's domain requires single sign-on | Send the person through “Sign in with SSO” |
| `sso_not_configured` | — | SSO was tried for a domain with no enabled connection (in the `error` query param) | Use another sign-in method |
| `code_required` | 400 | Adding a factor needs a current code or a security key confirmation | Ask for a code, or call `confirmWithSecurityKey()` |
| `security_key_invalid` | 400 | The key's answer couldn't be verified | Try again, or use a code |
| `security_key_cancelled` / `security_key_unsupported` | — | Browser prompt closed, or no security key support (SDK only) | Let the person retry or use a code |
| `security_key_exists` / `too_many_keys` | 409 / 400 | Key already added, or 5 keys already | Nothing to do / remove one first |
| `no_security_key` | 400 | A key action on an account with no keys | Use a code |
| `sms_failed` / `sms_disabled` | 400 | The text couldn't be sent, or SMS isn't on for this app | Check the number, or use another method |
| `sms_country_not_allowed` | 400 | Numbers in that country aren't allowed | Use another method |
| `sign_up_not_allowed` | 403 | The email breaks the app's sign-up rules | Ask for another address |
| `captcha_required` / `captcha_failed` | 400 | The human check is on and the answer was missing, wrong, used, or couldn't be verified | Show a fresh widget and retry |
| `two_factor_setup_required` | 403 | The app (or organization) requires two-step verification and it's off | Send the person to the account page |
| `two_factor_required_first` | 400 | An admin tried to require two-factor without having it | Turn it on for yourself first |
| `already_verified` | 400 | Email is already verified | Nothing to do |
| `unauthenticated` | 401 | No valid session or key | Sign in, or check your keys |
| `forbidden` | 403 | Origin not allowed, or account suspended | Add the origin, or contact support |
| `not_found` | 404 | No such user/session in this instance | |
| `rate_limited` | 429 | Too many attempts | Wait and retry |
| `internal_error` | 500 | Unexpected failure (details only in server logs) | Retry; report if it persists |
