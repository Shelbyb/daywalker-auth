---
title: Rotating keys
description: Rotate your instance signing keys without locking anyone out.
---

# Rotating keys

## Signing keys (per instance)

Signing keys sign the session tokens your app verifies. Rotating is safe to do any time.

In the dashboard, open your instance, then **Settings**, then **Signing keys**, and choose **Rotate**. Or call the API:

```bash
curl -X POST https://users.daywalker.dev/v1/instance/signing_keys/rotate \
  -H "Authorization: Bearer $DAYWALKER_SECRET_KEY"
```

The new key signs everything from now on. The old key is retired but stays in your public keys (JWKS) for 24 hours, so tokens already issued keep working. After that it is purged automatically.

