# Next steps (working notes)

Updated as work happens, so it can be picked up after a pause. The public roadmap is
[`content/docs/roadmap.md`](content/docs/roadmap.md).

## Current state

- `main` is green: 22 end-to-end suites pass (`npm run test:all` with the service on :3000; see README "Tests"), plus two
  Chromium walkthroughs: `scripts/browser/components.py` and `scripts/browser/securitykey.py` (virtual FIDO2 key).
- Done: signing-key rotation, `MASTER_KEY` rotation, audit logs, email codes and magic links, breached-password check,
  custom email templates, more social providers, drop-in React components, enterprise SSO (SAML), SMS two-factor, and
  the four follow-ups below ("SSO required", SMS country allow-list, security keys, SCIM).

## Just finished: follow-ups (after the roadmap)

- **"SSO required"** (migration 0013). `saml_connections.sso_required`; `src/lib/auth/sso-policy.ts` refuses password,
  sign-up, email code/magic link, password reset, passkey and social sign-in for addresses at an enforced domain
  (`403 sso_required`). Backstop: `createSession` refuses any session that isn't `method: "saml"`. A disabled connection
  doesn't enforce (no lockout). Uses the primary email. Switching it on revokes active sessions of users at the connection's domains.
  Tests: end of `scripts/saml-e2e.ts`.
- **SMS country allow-list.** `settings.smsCountries` (calling codes like `1 44 49`), validated in `src/lib/sms.ts`
  (`parseCallingCodes`), enforced when a phone is *added* only (existing phones keep working). Dashboard Settings field.
- **Security keys as a second factor** (migration 0014). `mfa_security_keys` (separate from `passkeys`, so a key can never
  sign in alone), `src/lib/auth/security-keys.ts`, wrappers in `mfa.ts`, routes `mfa/security_keys/*` and
  `sign_in/second_factor/security_key`, SDK `addSecurityKey` etc., hosted and component UI. Adding/removing needs a current
  code (a key-only user uses a backup code). `scripts/soft-authenticator.ts` is the shared software authenticator;
  `scripts/securitykey-e2e.ts` (45 checks).
- **SCIM 2.0 provisioning** (migration 0015). Per SSO connection: bearer token (hash only, shown once, rotate/revoke),
  `/v1/scim/v2/{connectionId}/Users` (GET/POST/PUT/PATCH/DELETE, `userName`/`externalId` filters), discovery docs;
  `src/lib/auth/scim.ts`, `src/lib/scim-http.ts`. Manages only users it created or adopted, only at the connection's
  domains. `active:false` suspends + signs out. Backend `POST|DELETE /v1/saml_connections/{id}/scim_token`, dashboard card.
  `scripts/scim-e2e.ts` (58 checks). Tested with simulated Okta/Entra-style calls, not a real IdP yet.

## Just finished: more social providers (roadmap #7)

Microsoft, Apple, Discord, GitLab (incl. self-hosted) and generic OpenID Connect, tested by
`scripts/providers-e2e.ts` (33 checks, mock IdP on :3999 signing real ID tokens). Key points for later work:

- `src/lib/net-guard.ts` is the shared SSRF guard (`checkPublicUrl`, `guardedFetch`); use it for any URL a
  developer supplies (SAML metadata URLs next).
- `src/lib/auth/oauth-providers.ts` holds the provider registry; adding a provider = one entry in `DEFS`,
  `LABELS`, the enum (migration) and `parseSettings`.
- Microsoft emails are trusted only for personal accounts or `xms_edov: true` (nOAuth). Apple uses form POST +
  `SameSite=None` state cookie on HTTPS and a per-request ES256 client secret.
- Provider JWKS cached 10 min; refetched on unknown key / bad signature, at most every 30 s.

## Just finished: docs catch-up and a CI fix

API reference, SDK, error codes, security and overview docs now cover SMS, security keys (and key confirmation), SSO
required, SCIM, hosted components. CI fix: the job sets `WEBHOOK_ALLOW_PRIVATE` for the service, but the test process
must not have it (the webhook SSRF checks fail otherwise), so the suite loop runs `env -u WEBHOOK_ALLOW_PRIVATE`.
`npm audit --omit=dev` is clean. CI still hasn't run on GitHub.

## Just finished: SCIM Groups -> organization roles (migration 0016)

`/v1/scim/v2/{id}/Groups[/{gid}]` (create/get/list with `displayName eq`/PUT/PATCH members+name/DELETE; members must be users
the connection manages). Opt-in per connection: `scimAdminGroups` (lowercased names; dashboard SSO tab + backend PATCH).
Members of those groups become org admins, everyone else managed stays member; last admin never demoted; unmanaged people
untouched; SAML JIT uses the group role. Logic in `src/lib/auth/scim-roles.ts` + `scim-groups.ts`. New audit types
`scim_group.*`, `scim_role.changed`. ~30 new checks in scim-e2e.

## Just finished: security key confirms account changes

`mfa/security_keys/confirm/options` + `confirm`: a key touch stores `stepup:<sessionId>` (120 s, single use, bound to the
session). Add/remove factor, disable 2FA and new backup codes accept no code when that proof exists (`confirmed()` in
`mfa.ts`). SDK `confirmWithSecurityKey()`; account page "Use a security key instead". 20 new checks in securitykey-e2e.

## Just finished: hosted sign-in / sign-up use the drop-in components

`/sign-in` and `/sign-up` now render `<SignIn />` / `<SignUp />` (`src/app/components/hosted-auth.tsx`), so there is one
UI to maintain. The server validates the redirect against the instance allow-list and passes the settings
(`publicEnvironment`, shared with `/v1/client/environment`) so there is no loading flash. Error codes in the URL map to
fixed messages only. `AuthProvider` gained `syncCookie={false}` (hosted origin sets no app cookie); components gained
`initialEnvironment`, `initialError`, `signedIn`. Removed auth-form/email-code/verify-email. Verified with
`scripts/browser/securitykey.py` and the full e2e suites.

## Just finished: drop-in React components (roadmap #8)

`<SignIn />`, `<SignUp />`, `<UserButton />`, `<OrganizationSwitcher />` in `@daywalker/auth/react`
(`packages/sdk/src/react/components.tsx`, optional `styles.css`), demo at `examples/nextjs` `/components`,
browser walkthrough `scripts/browser/components.py`. Also fixed cross-origin SDK use (publishable key in the
query string for CORS preflights; CORS headers on error responses).

## Just finished: enterprise SSO with SAML (roadmap #9)

`src/lib/auth/saml.ts` (on `@node-saml/node-saml`), connections per instance routed by email domain
(`saml_connections`, `saml_domains`), SP-initiated only, state cookie + exact `InResponseTo` binding, issuer
check, domain-ownership rule for emails, JIT org membership. Dashboard **SSO** tab, backend
`/v1/saml_connections`, hosted and component "Sign in with SSO" buttons, SDK `checkSSO` / `signInWithSSO`.
`scripts/saml-e2e.ts` (38 checks incl. unsigned, wrong key, tampering, signature wrapping, audience, expiry,
issuer, replay, IdP-initiated, cross-connection, login CSRF, foreign domain). Needs `openssl` on the runner.
Possible follow-ups: optional "SSO required" enforcement per domain (block password sign-in), SCIM provisioning.

## Just finished: SMS two-factor (roadmap #10)

Twilio Verify (`src/lib/sms.ts`), opt-in second factor only, per-instance "Allow SMS two-factor" switch
(needs `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_VERIFY_SERVICE_SID`). `mfa_sms` table (phone encrypted).
Adding any second factor to an account that already has one requires a current code (anti-persistence).
`scripts/sms-e2e.ts` (32 checks, mock Twilio on :3995). Also fixed a hosted sign-in bug: after 2FA with no
redirect URL the form stayed on the 2FA step.

## Possible follow-ups (not started; ask Shelby)

- Try SCIM (Users and Groups) against a real Okta or Entra ID trial; only simulated IdP calls are tested so far.
- SAML single logout; IdP-initiated sign-in (currently refused on purpose).

## Open items for Shelby (not blocking)

- Docker image: the sandbox has no Docker daemon, so the image itself is still unbuilt. What I could check without it
  passed: the bundled `migrate.mjs` runs, and the standalone server starts and answers `/healthz`.
- DigitalOcean `.do/app.yaml`: `${db.DATABASE_URL}`, `${db.CA_CERT}`, `${cache.DATABASE_URL}` and `engine: VALKEY` match
  DigitalOcean's docs. A first real deploy is still the proof.
- Decide `PASSKEY_RP_ID` before launch (`daywalker.dev` suggested). Security keys use the same RP ID as passkeys.
- CI workflow hasn't run on GitHub yet (it now includes the security-key and SCIM suites).
- Commits show "Unverified" on GitHub because they aren't signed; set up SSH/GPG signing to get "Verified".
- Old SHAs from the earlier history rewrite may linger on GitHub (only GitHub support can purge them).
- Delete the leftover branches `wip/social-providers`, `wip/components`, `wip/saml` and `wip/sms` on GitHub (same commit as main; this session isn't allowed to delete branches).

## How to resume locally

```bash
npm ci && npm run db:migrate && npm run build
# service: WEBHOOK_ALLOW_PRIVATE=1 ALLOW_INSECURE_TRANSPORT=1 OAUTH_TEST_BASE_URL=http://localhost:3999 \
#   PWNED_PASSWORDS_TEST_URL=http://localhost:3997 TWILIO_TEST_BASE_URL=http://localhost:3995 \
#   TWILIO_ACCOUNT_SID=AC000… TWILIO_AUTH_TOKEN=… TWILIO_VERIFY_SERVICE_SID=VA000… (see ci.yml) node .next/standalone/server.js  (or next start)
npm run test:all
# test notes: Python Playwright is needed for scripts/browser/*.py; run `npx tsx scripts/browser/seed-pk.ts` for a fresh publishable key.
```

Commits: author Shelbyb `<Shelbyb@users.noreply.github.com>`, no co-author or attribution trailers.
