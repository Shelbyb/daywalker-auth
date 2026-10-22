# Next steps (working notes)

Updated as work happens, so it can be picked up after a pause. The public roadmap is
[`content/docs/roadmap.md`](content/docs/roadmap.md).

## Current state

- `main` is green: 18 end-to-end suites pass (`npm run test:all` with the service on :3000; see README "Tests").
- Done in this round: signing-key rotation, `MASTER_KEY` rotation, audit logs, email codes and magic links,
  breached-password check, custom email templates, more social providers.

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

## In progress: embeddable React components (roadmap #8), branch `wip/components`

Done (tested in a real browser with `scripts/browser/components.py`):
- `packages/sdk/src/react/components.tsx`: `<SignIn />` (password, passkey, social, email code, 2FA),
  `<SignUp />` (terms consent, social, email verification), `<UserButton />`, `<OrganizationSwitcher />`.
  No inline styles; `dw-*` classes; `appearance.classNames`; optional `@daywalker/auth/styles.css`.
- Demo pages in `examples/nextjs/src/app/components/*`.
- Fixed two real cross-origin bugs found by the browser test: the SDK now sends the publishable key in the
  query string too (browser CORS preflights carry no custom headers, so preflights were always refused), and
  error responses now carry CORS headers (`corsHeadersFor` in `src/lib/http.ts`), so browsers can show
  "Email or password is incorrect" instead of a network error. `scripts/sdk-e2e.ts` covers both.

Left to do: docs guide (`content/docs/guides/components.md`, SDK react page), README, roadmap, full
regression, merge to `main`.

## After that (in order)

9. Enterprise SSO (SAML).
10. SMS codes (needs a provider decision from Shelby, e.g. Twilio or Vonage).

## Open items for Shelby (not blocking)

- Docker image untested; DigitalOcean binding names in `.do/app.yaml` (`${db.CA_CERT}`, `${cache.DATABASE_URL}`)
  unverified.
- Decide `PASSKEY_RP_ID` before launch (`daywalker.dev` suggested).
- CI workflow hasn't run on GitHub yet.
- Commits show "Unverified" on GitHub because they aren't signed; set up SSH/GPG signing to get "Verified".
- Old SHAs from the earlier history rewrite may linger on GitHub (only GitHub support can purge them).
- Delete the leftover branch `wip/social-providers` on GitHub (same commit as main; this session isn't allowed to delete branches).

## How to resume locally

```bash
npm ci && npm run db:migrate && npm run build
# service: WEBHOOK_ALLOW_PRIVATE=1 ALLOW_INSECURE_TRANSPORT=1 OAUTH_TEST_BASE_URL=http://localhost:3999 \
#   PWNED_PASSWORDS_TEST_URL=http://localhost:3997 node .next/standalone/server.js  (or next start)
npm run test:all
```

Commits: author Shelbyb `<Shelbyb@users.noreply.github.com>`, no co-author or attribution trailers.
