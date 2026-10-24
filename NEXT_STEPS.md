# Next steps (working notes)

Updated as work happens, so it can be picked up after a pause. The public roadmap is
[`content/docs/roadmap.md`](content/docs/roadmap.md).

## Current state

- `main` is green: 22 end-to-end suites pass (`npm run test:all` with the service on :3000; see README "Tests"), plus two
  Chromium walkthroughs: `scripts/browser/components.py` and `scripts/browser/securitykey.py` (virtual FIDO2 key).
- Done: signing-key rotation, `MASTER_KEY` rotation, audit logs, email codes and magic links, breached-password check,
  custom email templates, more social providers, drop-in React components, enterprise SSO (SAML), SMS two-factor, and
  the four follow-ups below ("SSO required", SMS country allow-list, security keys, SCIM).

## In progress: security and org feature batch (resume here)

Order of work, one commit per feature, each with migration, API, UI, SDK, docs page and an e2e suite (added to
`test:all`, its own `test:<name>` and CI). Status is updated as each lands.

1. [x] Real account lockout (migration 0022, `auth/lockout.ts`, `scripts/lockout-e2e.ts`; see `guides/account-lockout.md`) (progressive, per account, Valkey + persistent state, email unlock link, admin unlock, `user.locked` / `user.unlocked`)
2. [x] Custom organization roles and permissions (migration 0023, `auth/org-roles.ts`, `auth/org-domains.ts`, `scripts/orgroles-e2e.ts`; `guides/organization-roles.md`). Domain verification by DNS TXT is tested only against the `DNS_TXT_TEST_FILE` stub, not real DNS; the email path uses role mailboxes (admin@, postmaster@ ...)
3. [x] SDK `<CreateOrganization/>` and `<OrganizationProfile/>` + hosted `/organization` and `/create-organization` (`packages/sdk/src/react/components.tsx`, `src/app/components/hosted-org.tsx`, `scripts/orgui-e2e.ts`, browser walkthrough `scripts/browser/organization.py` run locally with Chromium). Also made the hosted embed use the dark palette (titles were dark-on-dark on the hosted pages)
4. [x] Self-service account deletion + data export (migration 0024, `auth/account-deletion.ts`, `scripts/accountdeletion-e2e.ts`; `guides/account-deletion.md`). Re-auth by password / 2FA code / emailed code, grace period (default 14 days, instance setting), sign-in blocked while pending (backstop in `createSession`), single-use cancel link, purge job in `instrumentation.ts`, export rate limited 3/hour and audited. Not done: a dashboard control for the grace period (backend API `instance/account_deletion` only); purge job tested by calling it directly, not by waiting for the timer.

## In progress: security batch 2 (resume here)

One commit per feature, each with migration, API, UI, SDK, docs and an e2e suite (in `test:all`, its own script, CI).

1. [x] Device-bound sessions, DPoP RFC 9449 (migration 0025 `sessions.dpop_jkt`, `auth/dpop.ts`, enforcement in `auth/sessions.ts` via the request kept in `currentRequest` (AsyncLocalStorage set by `handler()`), `POST /v1/client/session/bind`, `GET|PATCH /v1/instance/device_binding`, dashboard Sessions select, SDK `core/dpop.ts` + `deviceKeyStore`, `authProxy` refresh page signs proofs; `guides/device-binding.md`, `scripts/binding-e2e.ts`). Redirect sign-ins (OAuth, SSO, magic link) start unbound and the SDK binds them within 2 minutes via `session/bind`. Not tested: a real browser's IndexedDB/WebCrypto (the SDK is exercised with an in-memory key store and Node WebCrypto); platform impersonation sessions are exempt by design. Migration `when` values in the journal are synthetic and ahead of the sandbox clock (use previous + 100000), otherwise drizzle skips the migration.
2. [x] Step-up auth (migration 0026 `sessions.first_factor_at/second_factor_at`, `auth/stepup.ts`, `GET|POST /v1/client/session/reverify[/passkey[/options]]`, token claims `auth_time` + `fva` (ages in seconds at issue, -1 = never), server SDK `requireRecentAuth`/`isRecentlyVerified`/`ReverificationRequiredError`, `core/fresh.ts` shared with the browser, `authFetch` retries once after the prompt, `<ReverificationPrompt/>` mounted by `<AuthProvider/>`, `guides/step-up-auth.md`, `scripts/stepup-e2e.ts`). A user-verified passkey counts as both factors; a security key touch is consumed from the existing `stepup:<session>` proof. Not tested: the React prompt in a real browser (no component test harness; logic is covered through the client methods).
3. [x] Tamper-evident audit log (migration 0027 `audit_events.seq/prev_hash/hash/data_digest/data_erased`, `audit_chains`, `audit_export_configs`; `audit-chain.ts`, `audit-export.ts`; `GET /v1/audit_events/verify|export`, `/v1/instance/audit_export[/push|/test]`; dashboard verify, download and bucket card; SDK `verifyAuditExport`; `scripts/auditchain-e2e.ts`)
4. [ ] Passkey-first sign-up and conditional UI

New-device sign-in alerts were dropped on purpose (not wanted).

Notes: lockout is deliberately not configurable yet (5 failures / 15 min, 5 min to 24 h). Existing mfa and securitykey
suites now unlock the account via `POST /v1/users/{id}/unlock` after their brute-force sections. Local run needed
Postgres 16 + redis-server started by hand (no Docker daemon). `dashboard-e2e` "platform instance is excluded" fails
locally only because `bootstrap:platform` wasn't run.

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

## Just finished: sign-up protection + required two-factor (migration 0018)

Protection (`src/lib/auth/signup-protection.ts`, `instance-policy.ts`, `GET|PATCH /v1/instance/protection`, dashboard
Settings card): allow/block domain lists (subdomains match), throwaway-address list (`disposable-email-domains`, ~120k),
applied to new accounts from password sign-up and social sign-in (not SSO/SCIM); one generic `sign_up_not_allowed`.
Turnstile on sign-up and email-code send: secret in `instances.captcha_secret_enc` (in rotation registry), server-side
siteverify via guardedFetch, single use, fails closed; `TURNSTILE_TEST_BASE_URL` mock in tests; CSP `frame-src
challenges.cloudflare.com`; components render the widget. Required 2FA (`two-factor-policy.ts`): app-wide after a grace
period → `issueToken` refuses (`two_factor_setup_required`), sign-in returns `jwt: null, twoFactorSetupRequired`
(session kept so the account page can enroll); SSO sessions exempt. Per org (`organizations.require_two_factor`): no
org claims / can't activate without 2FA; admins need 2FA themselves to turn it on. SDK: `needs_two_factor_setup`,
`state.twoFactorSetupRequired`, `captchaToken`, `setOrganizationTwoFactor`. Fixed: protection update merged into a
cached instance and could undo other settings. `scripts/protection-e2e.ts` (~50 checks) in test:all and CI.
Not covered by a test: the OAuth new-account path of the email rules (same function as sign-up), and the real
Turnstile widget in a browser (needs Cloudflare keys and network).

## Plans (approved order: 4, then 6, then 10)

### 4. Custom session-token claims
- Per-instance claim template in the dashboard/backend (`PUT /v1/instance/token_claims`): JSON object whose values are
  `{{user.public_metadata.x}}`, `{{user.email}}`, `{{org.role}}`, `{{org.slug}}`, literals. No code execution: a small
  path resolver over an allow-listed object (public metadata, primary email + verified, name, org id/slug/role).
- Reserved claims (`sub sid iss aud azp exp iat nbf org_id org_role act`) can't be overridden; max 4 KB rendered (tokens
  ride in headers/cookies); private metadata never reachable.
- Rendered in `issueToken` (cache rendered claims 60 s per session to keep refresh cheap; bust on user/org update).
- SDK `verifyToken` returns them as-is; types via generic `verifyToken<Claims>()`. Docs + e2e (reserved claim refused,
  private metadata unreachable, size limit, updates visible within a minute).

### 6. Support impersonation
- Backend only: `POST /v1/users/{id}/impersonation { actor: "support@…", reason, minutes ≤ 60 }` returns a one-time
  sign-in URL (token hashed, 60 s to use). Dashboard button with a required reason.
- Creates a normal session flagged `impersonated_by` (new `sessions.actor` columns), JWT gets RFC 8693 `act: { sub }`;
  max 60 min, can't be refreshed past that, no "remember me".
- While impersonating: can't change password/email/2FA/passkeys/security keys, delete the account, or create API-ish
  credentials (403 `impersonation_forbidden`); hosted pages and `<UserButton>` show a banner with "End".
- Not allowed for: banned users, users in an org requiring 2FA? (allowed, but audited), the platform's own dashboard
  instance. Audit `user.impersonation_started/ended` with actor + reason; webhook `session.impersonation_started`.
- Server SDK: `auth()` exposes `actor`; docs advise apps to log it. e2e: one-time URL, expiry, forbidden actions, audit.

### 10. Sign-in analytics dashboard
- Daily rollups table (`analytics_daily`: instance, day, sign_ups, sign_ins, active_users (HyperLogLog in Valkey per
  day → count), failed_sign_ins, mfa_users) updated from the audit events already written (no new tracking, no IPs).
- Backfill job from `audit_events` (90 days) + nightly rollup via the existing worker/cron route.
- Dashboard "Overview" page: 30/90-day charts (inline SVG, CSP-safe, no chart library), 2FA adoption %, sign-in
  methods split, top failure reasons. Backend `GET /v1/analytics?from&to`.
- Privacy: aggregates only, counts < 5 shown as "<5" to avoid singling people out.

## Just finished: SAML single logout (migration 0017)

`/v1/saml/{id}/slo` (GET redirect + POST binding). IdP-initiated: signed LogoutRequest → revoke every session linked to that
NameID on the connection (`saml_sessions`: NameID encrypted + blind index, also linked across the 2FA step), reply with
a signed LogoutResponse to the IdP's `sloUrl` (or 200 if none). SP-initiated (opt-in `singleLogout`): `DELETE
/v1/client/session {redirectUrl}` returns `ssoLogoutUrl` (signed LogoutRequest); IdP's answer → stored redirect only.
Own checks in `saml-logout.ts`: signature required (node-saml accepts unsigned redirect messages, and Next re-encodes the
query, so we verify decoded values under the common encodings), issuer, Destination, IssueInstant, one use per ID.
Per-connection SP key (RSA 2048, @peculiar/x509, private key encrypted, cert in metadata; `reflect-metadata` imported
first). "SSO required" now spares sessions that came through the IdP. SDK `signOut({ redirectUrl, singleLogout })`.
Dashboard: logout URL + switch. ~40 new checks in saml-e2e (91 total).

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

- After 4/6/10, the rest of the feature list: invite-only/waitlist sign-up, username/phone sign-in, acting as an OIDC provider.

- Try SCIM (Users and Groups) against a real Okta or Entra ID trial; only simulated IdP calls are tested so far.
- IdP-initiated SAML sign-in stays refused on purpose (unsolicited assertions); revisit only if a customer needs it.

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

## Clerk gap roadmap

| # | Gap | Priority | Scope | Status |
|---|-----|----------|-------|--------|
| 1 | Identifier allowlist/blocklist | P2 | Extend domain allow/block (`instance-policy.ts`) to per-email/phone identifiers | partial |
| 2 | Waitlist / restricted sign-up mode | P1 | Instance sign-up mode (public/restricted/waitlist) + waitlist entries & invite flow | missing |
| 3 | Lock user from dashboard | P3 | Ban exists (`banUser`); add manual lock/unlock with reason | partial |
| 4 | Session custom claims / JWT templates | P1 | Custom session claims + named JWT templates | planned (in progress) |
| 5 | Per-instance bot protection config | P3 | Turnstile toggle exists; add mode/strictness and per-flow options | partial |
| 6 | Org roles/permissions + domain auto-join | P1 | Custom roles/permissions, verified domains with suggest/auto-join | done (UI for domains comes with #3/#8) |
| 7 | Account Portal org pages | P2 | Hosted org switcher, create-org, org profile pages | done (create + profile; switcher is the component) |
| 8 | SDK org components | P2 | `OrganizationSwitcher` exists; add `CreateOrganization`, `OrganizationProfile` | done |
| 9 | Dev → prod instance cloning | P3 | Copy settings/branding/providers to a new production instance | missing |
| 10 | Satellite domains / multi-domain | P3 | Satellite domain config + cross-domain session sync | missing |

Session settings (lifetime, inactivity timeout, multi-session) are also planned (in progress) alongside #4.
