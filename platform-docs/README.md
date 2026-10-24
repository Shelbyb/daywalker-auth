# Platform docs archive (for AI assistants)

The public docs (`content/docs`, rendered at `/docs`) are for customers who create an instance and use the SDK. Anything that only the operator of the whole service controls was taken out of them: `MASTER_KEY`/`INDEX_KEY`, server environment variables, Twilio/Resend credentials, self-hosting and deployment. This folder keeps the removed content word for word so it can be put back later, for example as an operator-only docs section.

Nothing in this folder is rendered. `src/lib/docs.ts` only reads `content/docs`.

## What's here

| Path | What it is |
|---|---|
| `pages/self-hosting.md` | The deleted page `content/docs/self-hosting.md` (slug `self-hosting`) |
| `pages/deployment-digitalocean.md` | The deleted page `content/docs/deployment-digitalocean.md` (slug `deployment-digitalocean`) |
| `pages/backup-restore.md` | Operator runbook for backups, the restore drill (`npm run drill:backup`) and disaster restore. New page, not part of the removed content; nothing links to it yet |
| `patches/restore-platform-sections.patch` | A unified diff that puts back the removed sections in the pages that still exist, plus the two nav entries in `src/lib/docs.ts` |

The patch restores:
- `src/lib/docs.ts`: the `self-hosting` ("Self-hosting") and `deployment-digitalocean` ("Deploy on DigitalOcean") entries in `NAV`, under the "Operating it" section, between `security` and `troubleshooting`.
- `content/docs/guides/rotating-keys.md`: the `MASTER_KEY` / `INDEX_KEY` rotation section (`npm run keys:print-index-key`, `npm run keys:rotate-master`) and the Valkey note.
- `content/docs/security.md`: the HKDF key hierarchy derived from `MASTER_KEY`, the production startup checks (https `APP_URL`, Postgres `sslmode`, Valkey `rediss://`), and the `MASTER_KEY` and `X-Forwarded-For` proxy items under "Your responsibilities".
- `content/docs/guides/dashboard.md`: "First-time setup (service owners)" (`npm run bootstrap:platform`, `PLATFORM_PUBLISHABLE_KEY`, link to the DigitalOcean page).
- `content/docs/quickstart.md` and `content/docs/guides/custom-ui.md`: the `npm run seed` instructions.
- `content/docs/guides/two-factor.md`: Twilio Verify account setup and the `TWILIO_*` variables.
- `content/docs/roadmap.md`: the `MASTER_KEY` rotation row and the `MASTER_KEY` / DigitalOcean mentions.
- `content/docs/guides/email-codes.md`: "Valkey" instead of "the cache".

## How to restore

1. Copy the pages back:
   ```bash
   cp platform-docs/pages/self-hosting.md platform-docs/pages/deployment-digitalocean.md content/docs/
   ```
2. Apply the patch from the repo root:
   ```bash
   git apply --3way platform-docs/patches/restore-platform-sections.patch
   ```
   If it doesn't apply cleanly (the docs changed since it was made), read the patch and add each `+` block back by hand in the matching section. Keep any newer customer-facing wording.
3. Check that the old facts are still true before you publish: env var names in `src/lib/env.ts`, script names in `package.json`, `.do/app.yaml`, and the commands in `README.md`.
4. Decide who can see the restored pages. These pages were removed because customers shouldn't see them. Good options:
   - put them behind the platform admin dashboard (`/dashboard/platform`) instead of the public `/docs`, or
   - keep them in the repo only (for example `docs/operators/`) and don't add them to `NAV`.
   Only add them back to `NAV` in `src/lib/docs.ts` if they are meant to be public again.
5. Search `content/docs` and `src/` for links to `/docs/self-hosting` and `/docs/deployment-digitalocean` and fix any that point to pages that are no longer public. `README.md` currently points to `platform-docs/` for deployment and `MASTER_KEY` rotation. Point it back to `content/docs/...` if you restore the pages there.

The original versions are also in git history, in commit `389ddcc` and earlier (for example `git show 389ddcc:content/docs/security.md`).
