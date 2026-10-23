---
title: Two-factor authentication
description: Ask for a second step as well as a password: an authenticator app, a text message or a security key.
---

With two-factor authentication (2FA) turned on, signing in needs **something you know** (a password, or a Google/GitHub account) **and something you have** (a phone with an authenticator app). A stolen password on its own is no longer enough.

Daywalker Auth uses **TOTP**, the 6-digit codes that change every 30 seconds. It works with any standard app: Google Authenticator, Microsoft Authenticator, 1Password, Authy, Bitwarden, and others.

## How it works for your users

**Setup (once)**
1. In their account settings, the user chooses to turn on 2FA.
2. They scan a QR code with their authenticator app.
3. They type the 6-digit code the app shows, proving it's set up correctly.
4. They get **10 backup codes** to keep somewhere safe. Each one works once, for when their phone is lost.

**Every sign-in after that**
1. They enter their password, or use Google/GitHub, as usual.
2. They're asked for the current 6-digit code, or a backup code.
3. They're in.

## Using the hosted pages

- **Sign-in:** the hosted page shows the code step automatically when an account has 2FA, for both password and social sign-in.
- **Setup:** users turn 2FA on from the [hosted account page](/docs/guides/account-page), or you can build your own screen (below).

## Handling 2FA in your own sign-in form

`signIn` returns a **result** telling you whether a second step is needed:

```tsx
"use client";
import { useState } from "react";
import { useAuth, AuthError } from "@daywalker/auth/react";

export function SignIn() {
  const { signIn, completeSecondFactor } = useAuth();
  const [step, setStep] = useState<"password" | "code">("password");
  const [error, setError] = useState("");

  async function submitPassword(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    try {
      const result = await signIn({ email: f.get("email") as string, password: f.get("password") as string });
      if (result.status === "needs_second_factor") setStep("code");
      else window.location.assign("/dashboard");
    } catch (err) {
      setError(err instanceof AuthError ? err.message : "Try again");
    }
  }

  async function submitCode(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    try {
      await completeSecondFactor(new FormData(e.currentTarget).get("code") as string);
      window.location.assign("/dashboard");
    } catch (err) {
      setError(err instanceof AuthError ? err.message : "Try again");
    }
  }

  return step === "password" ? (
    <form onSubmit={submitPassword}>
      <input name="email" type="email" autoComplete="email" required />
      <input name="password" type="password" autoComplete="current-password" required />
      <button>Continue</button>
      {error && <p role="alert">{error}</p>}
    </form>
  ) : (
    <form onSubmit={submitCode}>
      <p>Enter the code from your authenticator app, or a backup code.</p>
      <input name="code" autoComplete="one-time-code" required autoFocus />
      <button>Verify</button>
      {error && <p role="alert">{error}</p>}
    </form>
  );
}
```

`completeSecondFactor` accepts either kind of code. Backup codes can be typed with or without the dash, in any case.

> **Note** The pending step lasts **5 minutes** and allows **5 wrong codes**. After that the user has to enter their password again.

## Building your own setup screen

```tsx
"use client";
import { useState } from "react";
import { useAuth } from "@daywalker/auth/react";
import QRCode from "qrcode"; // npm install qrcode

export function EnableTwoFactor() {
  const { startTotpSetup, confirmTotpSetup } = useAuth();
  const [qr, setQr] = useState<string>();
  const [secret, setSecret] = useState<string>();
  const [codes, setCodes] = useState<string[]>();

  async function begin() {
    const { uri, secret } = await startTotpSetup();
    setQr(await QRCode.toDataURL(uri)); // render the otpauth:// URI as a QR code
    setSecret(secret); // for people who can't scan
  }

  async function confirm(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCodes(await confirmTotpSetup(new FormData(e.currentTarget).get("code") as string));
  }

  if (codes)
    return (
      <div>
        <p>Save these backup codes now. They won&apos;t be shown again.</p>
        <ul>{codes.map((c) => <li key={c}><code>{c}</code></li>)}</ul>
      </div>
    );

  if (!qr) return <button onClick={begin}>Turn on two-factor authentication</button>;

  return (
    <form onSubmit={confirm}>
      <img src={qr} alt="QR code for your authenticator app" width={200} height={200} />
      <p>Can&apos;t scan? Enter this key: <code>{secret}</code></p>
      <input name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} required />
      <button>Confirm</button>
    </form>
  );
}
```

To turn it off, or to get fresh backup codes, the user must enter a current code. A stolen session alone can't remove their protection:

```ts
await disableTwoFactor(code);              // code: authenticator or backup
const fresh = await regenerateBackupCodes(code); // old backup codes stop working
```

## Text-message codes (SMS)

Users can also get their second-factor code by text message, instead of (or as well as) an authenticator app. It's **off by default**, because SMS is the weakest option: a determined attacker can hijack a phone number with a SIM swap. Offer it for people who won't install an app.

**Turn it on**

1. Create a [Twilio Verify](https://www.twilio.com/docs/verify) service. Twilio generates, sends and checks the codes, and handles fraud protection.
2. Set `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` and `TWILIO_VERIFY_SERVICE_SID` on the server.
3. In the dashboard, open **Settings** and tick **Allow SMS two-factor**.
4. Optional: under **SMS countries**, list the country calling codes people may add a phone from, like `1 44 49` for the US/Canada, UK and Germany. Leave it empty to allow every country. Limiting it is the best defence against SMS toll fraud, where someone enrols premium-rate numbers to run up your bill. It only applies when a phone is added: people who already have one keep it, so narrowing the list never locks anyone out. A number from another country gets the error `sms_country_not_allowed`.

Users then see **Use text messages** on the account page. At sign-in they get a **Text a code to •••• 0100** option.

**With the SDK**

```ts
// Account settings: add a phone (international format)
await auth.startSmsSetup("+1 415 555 0100");          // add `currentCode` if 2FA is already on
const backupCodes = await auth.confirmSmsSetup(code);  // new codes when this turns 2FA on, else []

// Sign-in, after signIn() returned needs_second_factor
const { sms } = await auth.getSecondFactorOptions();   // "•••• 0100" or null
await auth.sendSecondFactorSms();
await auth.completeSecondFactor(code, "sms");
```

**Safeguards**

- Adding a phone or an authenticator app to an account that already has two-factor needs a **current code**. Someone with a stolen session can't quietly add their own phone and keep access.
- Removing the phone or turning two-factor off also needs a current code: from the app, a text, or a backup code.
- Texts are limited per user, per phone number and per IP, so nobody can run up your Twilio bill.
- Phone numbers are encrypted at rest and only ever shown masked. No SMS code is stored here; Twilio checks them, and each works once.
- If you later turn the setting off, people who already use SMS can still sign in with it. Nobody gets locked out.

## Security keys (YubiKey and similar)

A hardware security key is the strongest second factor here: it can't be phished, because the key checks which website is asking, and nothing can be intercepted or SIM-swapped. It works with any FIDO2 key (YubiKey, Google Titan, Feitian, and others), and users can add up to 5.

Nothing to switch on. If the browser supports it, the account page shows **Add a security key**, and sign-in offers **Use a security key**.

**With the SDK**

```ts
// Account settings (needs a sign-in from the last 15 minutes)
const { id, backupCodes } = await auth.addSecurityKey({ name: "YubiKey", currentCode }); // currentCode only if 2FA is already on
const keys = await auth.listSecurityKeys();
await auth.removeSecurityKey(keys[0].id, code);

// Sign-in, after signIn() returned needs_second_factor
const { securityKey } = await auth.getSecondFactorOptions(); // true if the account has one
await auth.completeSecondFactorWithSecurityKey();            // the browser asks the person to touch the key
```

**Good to know**

- **A key can confirm account changes too.** Adding or removing a factor, turning two-factor off and making new backup codes normally need a current code. If the person has a security key, they can touch it instead (the account page shows **Use a security key instead**). In code, call `confirmWithSecurityKey()` and then the action with no code, e.g. `await client.confirmWithSecurityKey(); await client.disableTwoFactor();`. The confirmation lasts two minutes, works for one change, and only for the session that made it.
- **A security key is only a second factor.** It can never sign anyone in by itself. That's what [passkeys](/docs/guides/passkeys) are for, and they're stored separately.
- Adding or removing a key needs a **current code**, like every other factor. If a key is someone's only factor, they use a backup code for that, so keep the backup codes safe.
- The key's answer is checked against a one-time challenge for that sign-in. Replayed, forged and cloned keys (a signature counter that goes backwards) are refused, and five wrong tries void the sign-in.
- Only the key's public half is stored. Removing the last factor turns two-factor off and clears the backup codes.
- Keys work on your own domains the same way passkeys do. See `PASSKEY_RP_ID` in [passkeys](/docs/guides/passkeys) if your app runs on a different subdomain than the auth service.

## When a user is locked out

If someone loses their phone **and** their backup codes, an admin can remove 2FA with the backend API:

```bash
curl -X DELETE https://users.example.com/v1/users/user_123/mfa \
  -H "Authorization: Bearer $DAYWALKER_SECRET_KEY"
```

> **Warning** Confirm the person's identity through another channel before doing this. Otherwise, anyone who can talk your support team into it can bypass 2FA.

## Requiring 2FA

**For everyone in your app:** in the dashboard (**Settings → Require two-step verification for everyone**) or with `PATCH /v1/instance/protection { "requireTwoFactor": true, "twoFactorGraceDays": 7 }`.

- During the grace period nothing is blocked; the account page shows a reminder with the deadline.
- After it, people without two-factor can still sign in, but they get **no session token** until they set it up, so your backend never sees them. Sign-in answers `{ status: "complete", jwt: null, twoFactorSetupRequired: true }`, `signIn()` resolves `{ status: "needs_two_factor_setup" }`, and `useAuth().twoFactorSetupRequired` is true. Send them to the account page (`client.hostedUrl("account")`); the drop-in components do this for you. Their existing sessions stop getting tokens too, within a minute.
- Sessions that came through company SSO are exempt: the identity provider is in charge of MFA there.

**For one organization:** an admin calls `setOrganizationTwoFactor(orgId, true)` (they need two-factor on themselves first, so nobody locks themselves out), or your backend calls `PATCH /v1/organizations/{orgId} { "requireTwoFactor": true }`. Members without two-factor keep their account, but that organization can't be made active and never appears in their token (`org_id` is missing), so organization-scoped checks on your server fail safely.

**For some users only** (for example admins), check `twoFactorEnabled` on the server:

```ts
const user = await backend().users.get(userId);
if (!user.twoFactorEnabled) redirect("/settings/security?require=2fa");
```

## Security details

- **Secrets and phone numbers** are encrypted per user (AES-256-GCM).
- **Backup codes** are stored only as keyed hashes. Each is about 49 bits of randomness, uses no look-alike characters (0/o, 1/l/i), and is marked used atomically, so two simultaneous requests can't both spend the same code.
- **Codes can't be replayed.** Once a 6-digit code is accepted, that 30-second window is spent, so a code someone watched you type is useless.
- **Clock drift** of one step (±30 seconds) is tolerated.
- **No session exists** until the second factor succeeds. The pending step lives only in a 5-minute, `HttpOnly` cookie plus a server-side record.
