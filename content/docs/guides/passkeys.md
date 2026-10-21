---
title: Passkeys
description: Let people sign in with their fingerprint, face or device PIN instead of a password.
---

A **passkey** replaces a password with a key pair stored on the user's device: their phone, laptop, password manager or a security key.

- **Signing in** is one tap plus Face ID, a fingerprint or the device PIN.
- **Nothing to steal.** There's no password to phish, reuse or leak. The private key never leaves the device, and the server only ever sees a signature.
- **Bound to your domain.** A fake look-alike site can't use a passkey, because the browser won't release it there.

## How it works for your users

**Adding a passkey (once per device)**
1. Signed in, they choose **Add a passkey** on the [account page](/docs/guides/account-page).
2. Their device asks them to confirm with Face ID, a fingerprint or the device PIN.
3. Done. Passkeys from Apple, Google and most password managers also sync to their other devices.

**Signing in**
1. They click **Sign in with a passkey**. No email to type.
2. They pick their account in the browser prompt and confirm.
3. They're in.

## Using the hosted pages

- **Sign-in:** a **Sign in with a passkey** button appears automatically in browsers that support passkeys.
- **Adding and managing:** users add, rename and remove passkeys from the [account page](/docs/guides/account-page).

## In your own UI

```tsx
"use client";
import { useAuth, AuthError } from "@daywalker/auth/react";

export function PasskeySignIn() {
  const { passkeysSupported, signInWithPasskey } = useAuth();
  if (!passkeysSupported()) return null; // hide the button where it can't work

  return (
    <button
      onClick={async () => {
        try {
          await signInWithPasskey();
          window.location.assign("/dashboard");
        } catch (err) {
          // The user closing the prompt isn't worth an error message
          if (err instanceof AuthError && err.code !== "passkey_cancelled") alert(err.message);
        }
      }}
    >
      Sign in with a passkey
    </button>
  );
}
```

Adding and managing passkeys:

```ts
const { registerPasskey, listPasskeys, renamePasskey, deletePasskey } = useAuth();

await registerPasskey("Work laptop");     // name is optional; users can rename later
const passkeys = await listPasskeys();    // [{ id, name, synced, lastUsedAt, createdAt }]
await renamePasskey(passkeys[0].id, "Personal phone");
await deletePasskey(passkeys[0].id);
```

### "Please sign in again"

Adding a passkey creates a long-lasting way into the account. To stop someone who got hold of an old or hijacked session from quietly adding their own, `registerPasskey` needs a session that **started in the last 15 minutes**. Otherwise it rejects with `reauth_required`:

```ts
try {
  await registerPasskey();
} catch (err) {
  if (err instanceof AuthError && err.code === "reauth_required") {
    // Send them to sign in, then back here to try again
  }
}
```

## Passkeys and two-factor authentication

A passkey sign-in already needs two things: the device (something you have) and the face, fingerprint or PIN that unlocks it (something you are or know). So it **counts as two factors**, and accounts with [two-factor authentication](/docs/guides/two-factor) aren't asked for a code afterwards. Password and Google/GitHub sign-ins still need the code.

## Using passkeys on your app's own domain

Passkeys belong to one domain, called the **relying party ID**. By default that's the auth service's hostname, e.g. `users.example.com`, which works with the hosted pages.

To use passkeys directly in your app at `app.example.com`, set the auth service's relying party ID to the shared parent domain:

```bash
PASSKEY_RP_ID=example.com
```

Then add `https://app.example.com` to the instance's allowed origins. Any allowed origin under that domain can register and use passkeys.

> **Warning** Choose this before users start registering passkeys. Each passkey is tied to the relying party ID it was created under, and changing the ID later makes existing passkeys stop working.

## Security details

- **User verification is required** when adding and when using a passkey, so a device left unlocked on a desk isn't enough.
- **Challenges are random, last 5 minutes, and work once.** A captured response can't be replayed.
- **Cloned-authenticator detection:** if a device's signature counter ever goes backwards, the sign-in is refused.
- **Origin and domain checks:** responses from any origin outside your instance's allowed list are rejected.
- **Only public keys are stored.** A database leak exposes nothing that can be used to sign in.
- **Every failure** (unknown passkey, bad signature, expired challenge) returns the same `passkey_invalid` error, so attackers learn nothing about which part failed.
