# Next steps (working notes)

Updated as work happens, so it can be picked up after a pause. The public roadmap is
[`content/docs/roadmap.md`](content/docs/roadmap.md).

## Current state

- `main` is green: 19 end-to-end suites pass (plus the components browser walkthrough) (`npm run test:all` with the service on :3000; see README "Tests").
- Done in this round: signing-key rotation, `MASTER_KEY` rotation, audit logs, email codes and magic links,
  breached-password check, custom email templates, more social providers, drop-in React components, enterprise SSO (SAML).

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

## Next: SMS codes (roadmap #10)

Decided by Shelby: **Twilio**, as an **opt-in second factor only** (no SMS sign-in).

Plan:
- Twilio Verify API (Twilio generates, sends and checks the codes, with its fraud guard and rate limits), configured
  once per deployment with `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_VERIFY_SERVICE_SID`; off unless set.
- Per-instance switch "Allow SMS two-factor" (default off).
- `mfa_sms` table: user, phone (encrypted, E.164, blind index), verified_at. Enrol: send code → confirm. Use at
  sign-in as an alternative to the authenticator app; backup codes still work. Changing or removing the number
  needs a current second factor.
- Strict limits: per user, per phone number and per IP; country allow-list option; audit events.
- Tests: mock Twilio Verify on a local port (`TWILIO_TEST_BASE_URL`, refused on HTTPS deployments).

## Open items for Shelby (not blocking)

- Docker image untested; DigitalOcean binding names in `.do/app.yaml` (`${db.CA_CERT}`, `${cache.DATABASE_URL}`)
  unverified.
- Decide `PASSKEY_RP_ID` before launch (`daywalker.dev` suggested).
- CI workflow hasn't run on GitHub yet.
- Commits show "Unverified" on GitHub because they aren't signed; set up SSH/GPG signing to get "Verified".
- Old SHAs from the earlier history rewrite may linger on GitHub (only GitHub support can purge them).
- Delete the leftover branches `wip/social-providers`, `wip/components` and `wip/saml` on GitHub (same commit as main; this session isn't allowed to delete branches).

## How to resume locally

```bash
npm ci && npm run db:migrate && npm run build
# service: WEBHOOK_ALLOW_PRIVATE=1 ALLOW_INSECURE_TRANSPORT=1 OAUTH_TEST_BASE_URL=http://localhost:3999 \
#   PWNED_PASSWORDS_TEST_URL=http://localhost:3997 node .next/standalone/server.js  (or next start)
npm run test:all
```

Commits: author Shelbyb `<Shelbyb@users.noreply.github.com>`, no co-author or attribution trailers.
