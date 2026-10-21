---
title: Email verification
description: Confirm that people own the email address they signed up with.
---

Anyone can type any email address into a sign-up form. Verification proves the person can read that inbox. Without it, someone could sign up as `ceo@yourcustomer.com`.

## How it works

1. The user signs up and is signed in, with their email marked `verified: false`.
2. Daywalker Auth emails them a **6-digit code**.
3. They enter it, and the email becomes `verified: true`.

Codes have these rules:

- A code expires after **10 minutes**.
- It works **once**.
- It allows **5 wrong guesses**, then it's destroyed.
- Asking for a new code replaces the old one.
- Only a keyed hash of each code is stored, never the code itself.

## Using the hosted pages

Nothing to do. After someone signs up on the hosted page, they're asked for the code before being sent back to your app.

## Building it into your own UI

```tsx
"use client";
import { useState } from "react";
import { useAuth, useUser, AuthError } from "@daywalker/auth/react";

export function VerifyEmail() {
  const { sendVerificationCode, verifyEmail } = useAuth();
  const { user } = useUser();
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");

  if (!user || user.emailAddresses[0]?.verified) return null;

  return sent ? (
    <form
      onSubmit={async (e) => {
        e.preventDefault();
        const code = new FormData(e.currentTarget).get("code") as string;
        try {
          await verifyEmail(code);
        } catch (err) {
          setError(err instanceof AuthError ? err.message : "Try again");
        }
      }}
    >
      <input name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} />
      <button>Verify</button>
      {error && <p role="alert">{error}</p>}
    </form>
  ) : (
    <button onClick={async () => { await sendVerificationCode(); setSent(true); }}>
      Verify {user.emailAddresses[0].email}
    </button>
  );
}
```

`autoComplete="one-time-code"` lets phones offer the code straight from the email notification.

## Requiring a verified email

Check the flag before letting someone do something sensitive:

```ts
import { auth, backend } from "@daywalker/auth/nextjs";

export async function POST() {
  const { userId } = await auth();
  if (!userId) return Response.json({ error: "Not signed in" }, { status: 401 });

  const user = await backend().users.get(userId);
  if (!user.emailAddresses.some((e) => e.primary && e.verified))
    return Response.json({ error: "Verify your email first" }, { status: 403 });

  // …invite teammates, publish, etc.
}
```

## Limits

- Sending: 5 codes per user per hour.
- Checking: 20 attempts per IP per 15 minutes, on top of the 5-guesses-per-code rule.
