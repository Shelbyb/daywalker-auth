---
title: Rotating keys
description: Rotate signing keys and your MASTER_KEY without locking anyone out.
---

# Rotating keys

Daywalker uses two kinds of secrets. You can rotate both.

## Signing keys (per instance)

Signing keys sign the session tokens your app verifies. Rotating is safe to do any time.

In the dashboard, open your instance, then **Settings**, then **Signing keys**, and choose **Rotate**. Or call the API:

```bash
curl -X POST https://users.daywalker.dev/v1/instance/signing_keys/rotate \
  -H "Authorization: Bearer $DAYWALKER_SECRET_KEY"
```

The new key signs everything from now on. The old key is retired but stays in your public keys (JWKS) for 24 hours, so tokens already issued keep working. After that it is purged automatically.

## MASTER_KEY

`MASTER_KEY` encrypts personal data at rest: names, emails, 2FA secrets, webhook URLs and secrets, signing keys and more. Rotate it if you think it leaked, or on a schedule.

Lookups by email use a blind index. To keep those working while the master key changes, the index key is pinned separately as `INDEX_KEY`.

1. **Pin the index key first.** With your current key set, run `npm run keys:print-index-key` and add the printed `INDEX_KEY=...` to your environment. Redeploy.
2. **Generate a new key:** `openssl rand -base64 48`.
3. **Schedule a short maintenance window.** The rotation locks the encrypted tables while it runs.
4. **Rehearse:** `OLD_MASTER_KEY=... NEW_MASTER_KEY=... INDEX_KEY=... DRY_RUN=1 npm run keys:rotate-master`. Nothing is changed.
5. **Run it for real** without `DRY_RUN`. It re-encrypts every value in one transaction, verifies each one, and rolls back on any error.
6. **Set `MASTER_KEY` to the new value**, keep `INDEX_KEY`, and redeploy.

Running it again with the old key fails safely.

Rotating also resets short-lived state in Valkey: in-progress sign-ins, 2FA challenges and rate-limit counters. Users may need to retry once.
