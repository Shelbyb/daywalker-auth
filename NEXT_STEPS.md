# Next steps (working notes)

Updated as work happens, so it can be picked up after a pause. The public roadmap is
[`content/docs/roadmap.md`](content/docs/roadmap.md).

## Current state

- `main` is green: 17 end-to-end suites pass (`npm run test:all` with the service on :3000; see README "Tests").
- Done in this round: signing-key rotation, `MASTER_KEY` rotation, audit logs, email codes and magic links,
  breached-password check, custom email templates.

## In progress: more social providers (roadmap #7)

Goal: Microsoft, Apple, Discord, GitLab and a generic OpenID Connect provider, alongside Google and GitHub.

Status: code written on branch `wip/social-providers` (type-checks; not yet tested). Next: extend the OAuth mock
and tests, browser check, docs, then merge into `main`.

Done so far:
- `src/lib/net-guard.ts`: SSRF guard shared by webhooks and OAuth (`checkPublicUrl`, `guardedFetch`).
- `src/lib/auth/oauth-providers.ts`: registry for all 7 providers, ID-token verification (jose), Apple client-secret
  JWT, OIDC discovery with issuer pinning, per-provider settings validation (`parseSettings`).
- `oauth.ts` uses the registry; nonce added to state; callback handles Apple's form POST; Apple state cookie is
  `SameSite=None` on HTTPS. Migration `drizzle/0010_more_providers.sql` (enum values + `settings` column).
- Dashboard social tab fields per provider; backend API accepts `settings`; hosted buttons use labels;
  environment endpoint adds `oauthProviderLabels`; SDK `OAuthProvider` type widened.

Plan:

1. Refactor `src/lib/auth/oauth.ts` into a provider registry (endpoints, scopes, profile mapping per provider).
2. Add `settings` (jsonb) to `oauth_providers` for per-provider extras: generic OIDC `issuer`, GitLab self-hosted
   base URL, Microsoft `tenant`, Apple `teamId` and `keyId`. Extend the `oauth_provider` enum (migration).
3. Verify ID tokens (jose + provider JWKS, issuer, audience, nonce) for Apple, Microsoft and generic OIDC.
4. Security rules that must hold:
   - Microsoft: only trust `email` as verified for personal accounts (consumer tenant) or when `xms_edov` is true
     (the "nOAuth" issue: work-account emails are editable by tenant admins).
   - Apple: client secret is a short-lived ES256 JWT made from the developer's `.p8` key (stored encrypted);
     Apple posts the callback (`response_mode=form_post`), so the callback needs a POST handler and the state
     cookie needs `SameSite=None; Secure` for Apple on HTTPS. The name arrives only on first sign-in.
   - Generic OIDC and self-hosted GitLab: discovery URL and every endpoint must be https and resolve to a public
     IP (reuse the SSRF guard from `src/lib/webhooks.ts`); pin the issuer.
5. Dashboard social tab and backend API accept the new fields; hosted sign-in shows the new buttons.
6. Extend `scripts/oauth-e2e.ts` mock (port 3999) for each provider; docs guide; README; roadmap; commit.

## After that (in order)

7. Embeddable React components: `<SignIn />`, `<SignUp />`, `<UserButton />`, `<OrganizationSwitcher />`.
8. Enterprise SSO (SAML).
9. SMS codes (needs a provider decision from Shelby, e.g. Twilio or Vonage).

## Open items for Shelby (not blocking)

- Docker image untested; DigitalOcean binding names in `.do/app.yaml` (`${db.CA_CERT}`, `${cache.DATABASE_URL}`)
  unverified.
- Decide `PASSKEY_RP_ID` before launch (`daywalker.dev` suggested).
- CI workflow hasn't run on GitHub yet.
- Commits show "Unverified" on GitHub because they aren't signed; set up SSH/GPG signing to get "Verified".
- Old SHAs from the earlier history rewrite may linger on GitHub (only GitHub support can purge them).

## How to resume locally

```bash
npm ci && npm run db:migrate && npm run build
# service: WEBHOOK_ALLOW_PRIVATE=1 ALLOW_INSECURE_TRANSPORT=1 OAUTH_TEST_BASE_URL=http://localhost:3999 \
#   PWNED_PASSWORDS_TEST_URL=http://localhost:3997 node .next/standalone/server.js  (or next start)
npm run test:all
```

Commits: author Shelbyb `<Shelbyb@users.noreply.github.com>`, no co-author or attribution trailers.
