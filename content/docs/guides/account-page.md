---
title: Account page
description: A ready-made settings page where users manage their profile, password, two-step verification and devices.
---

Every app eventually needs an "account settings" screen. Daywalker Auth hosts one for you at `/account`, with nothing to build.

## What users can do there

| Section | What it does |
|---|---|
| **Profile** | Edit first and last name |
| **Email address** | See their address and whether it's verified |
| **Password** | Change it (needs the current password). Other devices are signed out. |
| **Passkeys** | Add one (needs a recent sign-in), rename or remove it |
| **Two-step verification** | Turn it on with a QR code, save backup codes, create new codes, or turn it off |
| **Connected accounts** | See which Google/GitHub accounts can sign in |
| **Where you're signed in** | See every device with browser, OS, approximate location and last activity; sign any of them out |

## Linking to it

The easiest way is `<UserButton>`: its menu already has a **Manage account** item that opens the page and links back to where the user came from.

```tsx
"use client";
import { UserButton } from "@daywalker/auth/react";

export function Header() {
  return <UserButton afterSignOutUrl="/" />;
}
```

For your own link, use `hostedUrl`:

```tsx
"use client";
import { useAuthClient } from "@daywalker/auth/react";

export function SettingsLink() {
  const client = useAuthClient();
  return <a href={client.hostedUrl("account", window.location.href)}>Account settings</a>;
}
```

The second argument becomes a **← Back to your app** link at the top of the page. Like every redirect, it must be on your instance's allowed origins; otherwise the back link is hidden.

If the user isn't signed in when they open the page, they're asked to sign in first and then brought back to it.

## Building your own settings screen

Everything the hosted page does is available in the SDK, so you can build the same screens in your own design:

```tsx
"use client";
import { useEffect, useState } from "react";
import { useAuth, type SessionInfo } from "@daywalker/auth/react";

export function Devices() {
  const { listSessions, revokeSession, revokeOtherSessions } = useAuth();
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const reload = () => listSessions().then(setSessions);
  useEffect(() => { reload(); }, []);

  return (
    <div>
      <ul>
        {sessions.map((s) => (
          <li key={s.id}>
            {s.device} {s.current ? "(this device)" : ""}, {s.ipHint ?? "unknown location"}
            {!s.current && <button onClick={async () => { await revokeSession(s.id); reload(); }}>Sign out</button>}
          </li>
        ))}
      </ul>
      <button onClick={async () => { await revokeOtherSessions(); reload(); }}>Sign out everywhere else</button>
    </div>
  );
}
```

The other building blocks:

```ts
const { updateProfile, changePassword, getSecurity } = useAuth();

await updateProfile({ firstName: "Grace", lastName: null }); // null clears a field

const { otherSessionsSignedOut } = await changePassword({ currentPassword, newPassword });

const { hasPassword, twoFactorEnabled, backupCodesRemaining, connectedAccounts } = await getSecurity();
```

For two-step verification setup, see [Two-factor authentication](/docs/guides/two-factor#building-your-own-setup-screen).

## Why it behaves the way it does

- **Changing your password needs the current one.** Otherwise someone who briefly got into a signed-in browser could lock the real owner out.
- **Changing your password signs out every other device.** If you're changing it because you think it leaked, the intruder loses access straight away.
- **Turning off 2FA needs a current code**, for the same reason.
- **Locations are approximate.** Only the start of the IP address is shown, enough to spot "that's not my city" without revealing the full address.
- **Accounts created with Google/GitHub have no password.** For them the Password section offers **Set a password**, which goes through the email-code reset flow, so a hijacked session can't quietly add one.
