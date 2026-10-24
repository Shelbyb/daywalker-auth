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
| `passkey_signup_disabled` | 400 | Sign-up with a passkey isn't turned on for this app | Turn it on in Settings, or use another sign-up method |
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
| `unknown_role` | 400 | The role doesn't exist | Choose one from the roles list |
| `role_exceeds_yours` | 403 | You can't assign or change a role with more access than yours | Ask an admin |
| `role_in_use` | 409 | A role is still used by members, invitations, domains or settings | Move them first |
| `role_not_allowed` | 400 | A domain-join role can't manage the organization | Pick a role without manage permissions |
| `domain_taken` | 409 | Another organization already verified that domain | Use a different domain |
| `verification_failed` | 400 | DNS record not found yet | Wait for DNS, then retry |
| `account_locked` | 429 | Too many wrong passwords or codes; the account is locked for a while (same response for unknown emails) | Tell the user to wait or use the emailed unlock link |
| `account_pending_deletion` | 403 | Account is scheduled for deletion; sign-in refused | Use the cancel link from the email |
| `reverification_required` | 403 | (From *your* API, via `requireRecentAuth`.) The person must prove a factor again; body has `error.reverification: { level, maxAge }` | `authFetch` handles it; or call the `reverify*` methods and retry |
| `no_second_factor` | 400 | Re-verifying with a code on an account with no two-factor | Offer another way |
| `security_key_required` | 400 | `factor: security_key` without a recent security key touch | Run `mfa/security_keys/confirm` first |
| `no_passkey` | 400 | Re-verifying with a passkey but none is registered | Offer another way |
| `device_key_required` | 400 | The app requires device-bound sessions and the request had no DPoP proof | Use the SDK, or send a `DPoP` header |
| `device_proof_required` | 401 | The session is bound to a device key and the request had no proof | Send a DPoP proof signed by the session's key |
| `invalid_dpop_proof` | 401 | Bad, stale, replayed or wrong-key DPoP proof | Make a new proof for this method and URL |
| `device_binding_required` | 401 | The app requires device binding and this session isn't bound | Sign in again |
| `already_bound` | 409 | The session already has a device key | None; keys are never replaced |
| `bind_window_closed` | 403 | Too long since sign-in to bind this session | Sign in again |
| `device_binding_off` | 400 | Binding is not enabled for this app | None |
| `account_deletion_disabled` | 403 | The app turned off self-service deletion | Contact the app |
| `sole_org_admin` | 409 | Only admin of an organization that has other members | Promote another admin or delete the organization |
| `invalid_cancel_link` | 400 | Cancel link used or expired | Ask support, or sign in if already canceled |
| `credentials_required` | 400 | Re-authentication missing (password, code or emailed code) | Ask for what `me/reauth_code` lists |
| `invalid_unlock_link` | 400 | Unlock link used or expired | Sign in again to get a new link |
| `export_failed` | 400 | The audit log bucket rejected or could not be reached | Check the bucket settings and credentials; the message has the bucket's reason |
| `rate_limited` | 429 | Too many attempts | Wait and retry |
| `internal_error` | 500 | Unexpected failure (details only in server logs) | Retry; report if it persists |
| `clone_target_not_production` | 400 | Config cloning was called with a development secret key | Use the production instance's secret key |
| `no_development_instance` | 400 | The application has no development instance to clone from | Create one |
| `secrets_without_part` | 400 | `copySecrets` lists a part that isn't being copied | Include the part or drop the secret |
| `environment_exists` | 409 | The application already has an instance for that environment | None |
| `provider_needs_secret` | 400 | Tried to enable a social provider that has no client secret | Set the secret first |
| `api_keys_disabled` | 403 | End-user API keys aren't enabled for this app | Enable them in the dashboard |
| `scope_not_allowed` | 400 | A self-service API key asked for a scope outside the allowed list | Use an allowed scope |
| `expiry_required` | 400 | The app requires API keys to expire within a set number of days | Pass `expiresInDays` |
| `invalid_subject` | 400 | An API key needs exactly one of `userId` or `orgId` | Fix the request |
| `invalid_satellite` | 400/403 | The return origin isn't a verified satellite domain of this app | Add and verify the domain |
| `primary_mismatch` | 400 | The satellite's `primaryDomain` differs from the app's | Fix the config |
| `invalid_challenge` | 400 | Missing or malformed handshake challenge | Use the SDK |
| `invalid_code` | 400 | The handshake code is wrong, used, expired or its satellite was removed | Start the sync again |
| `invalid_domain` | 400 | Not a valid domain (https required, no path) | Enter a domain like example.org |
| `domain_not_allowed` | 400 | localhost on a production instance, or the service's own domain | Use a real domain |
| `domain_exists` | 409 | That satellite is already added | None |
| `domain_taken` | 409 | The domain is already verified by another app | Contact support |
| `domain_is_primary` / `domain_is_satellite` | 400 | The domain is already the primary / a satellite | Pick another |
| `verification_failed` | 400 | The DNS TXT record wasn't found | Publish it and retry |
