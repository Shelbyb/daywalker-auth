# Next steps (working notes)

Updated as work happens, so it can be picked up after a pause. The public roadmap is
[`content/docs/roadmap.md`](content/docs/roadmap.md).

## Current state

- `main` is green: 18 end-to-end suites pass (plus the components browser walkthrough) (`npm run test:all` with the service on :3000; see README "Tests").
- Done in this round: signing-key rotation, `MASTER_KEY` rotation, audit logs, email codes and magic links,
  breached-password check, custom email templates, more social providers, drop-in React components.

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

## Next: enterprise SSO with SAML (roadmap #9), branch `wip/saml`

Plan:
- Library: `@node-saml/node-saml` 5.x (maintained passport-saml core; xml-crypto with the 2025 signature-wrapping
  fixes). Never hand-roll XML signature checks.
- `saml_connections` table per instance: name, optional organization, IdP entity ID, SSO URL, IdP signing
  certificate(s), verified email domains (unique per instance), enabled. Configure from the dashboard and
  backend API (paste IdP metadata XML or fields; metadata URLs fetched only through `net-guard`).
- SP-initiated only: the user types their email, the domain picks the connection, we send a signed-state
  AuthnRequest; IdP-initiated responses are refused. ACS is a cross-site POST, so the state cookie is
  `SameSite=None; Secure` on HTTPS (like Apple).
- ACS checks: signed assertion required, issuer, audience, recipient/destination, time window, `InResponseTo`
  matches our request, assertion ID single-use (replay cache), email domain must be one of the connection's
  verified domains. Then link/create the user (JIT) and add them to the connection's organization.
- Tests: a mock IdP that signs assertions with xml-crypto, plus attacks (unsigned, wrong key, signature
  wrapping, wrong audience, expired, replay, IdP-initiated, foreign domain).

## After that

10. SMS codes (needs a provider decision from Shelby, e.g. Twilio or Vonage).

## Open items for Shelby (not blocking)

- Docker image untested; DigitalOcean binding names in `.do/app.yaml` (`${db.CA_CERT}`, `${cache.DATABASE_URL}`)
  unverified.
- Decide `PASSKEY_RP_ID` before launch (`daywalker.dev` suggested).
- CI workflow hasn't run on GitHub yet.
- Commits show "Unverified" on GitHub because they aren't signed; set up SSH/GPG signing to get "Verified".
- Old SHAs from the earlier history rewrite may linger on GitHub (only GitHub support can purge them).
- Delete the leftover branches `wip/social-providers` and `wip/components` on GitHub (same commit as main; this session isn't allowed to delete branches).

## How to resume locally

```bash
npm ci && npm run db:migrate && npm run build
# service: WEBHOOK_ALLOW_PRIVATE=1 ALLOW_INSECURE_TRANSPORT=1 OAUTH_TEST_BASE_URL=http://localhost:3999 \
#   PWNED_PASSWORDS_TEST_URL=http://localhost:3997 node .next/standalone/server.js  (or next start)
npm run test:all
```

Commits: author Shelbyb `<Shelbyb@users.noreply.github.com>`, no co-author or attribution trailers.
