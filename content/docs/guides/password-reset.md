---
title: Password reset
description: Let people who forgot their password get back in, safely.
---

## How it works

1. The user enters their email on the **Forgot password** page.
2. If an account exists, a 6-digit code is emailed. The page says the same thing either way.
3. The user enters the code and a new password.
4. The password is changed, the email is marked verified, and **every existing session is signed out**.

Two design choices are worth knowing about.

**The response never reveals whether an email has an account.** Otherwise anyone could check whether `someone@example.com` uses your app.

**All sessions end on reset.** People usually reset because they think someone else may know their password. If that someone is already signed in, the reset needs to kick them out too.

## Using the hosted pages

The sign-in page has a **Forgot password?** link to `/forgot-password`. To link there yourself:

```tsx
"use client";
import { useAuthClient } from "@daywalker/auth/react";

export function ForgotLink() {
  const client = useAuthClient();
  return <a href={client.hostedUrl("forgot-password", window.location.href)}>Forgot password?</a>;
}
```

## Building it into your own UI

```tsx
"use client";
import { useState } from "react";
import { useAuth, AuthError } from "@daywalker/auth/react";

export function ResetPassword() {
  const { requestPasswordReset, resetPassword } = useAuth();
  const [email, setEmail] = useState<string | null>(null);
  const [message, setMessage] = useState("");

  if (!email)
    return (
      <form onSubmit={async (e) => {
        e.preventDefault();
        const value = new FormData(e.currentTarget).get("email") as string;
        await requestPasswordReset(value);
        setEmail(value);
      }}>
        <input name="email" type="email" autoComplete="email" required />
        <button>Send code</button>
      </form>
    );

  return (
    <form onSubmit={async (e) => {
      e.preventDefault();
      const f = new FormData(e.currentTarget);
      try {
        await resetPassword({ email, code: f.get("code") as string, password: f.get("password") as string });
        setMessage("Password changed. Please sign in again.");
      } catch (err) {
        setMessage(err instanceof AuthError ? err.message : "Try again");
      }
    }}>
      <p>If {email} has an account, we sent it a code.</p>
      <input name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} required />
      <input name="password" type="password" autoComplete="new-password" required />
      <button>Set new password</button>
      {message && <p role="status">{message}</p>}
    </form>
  );
}
```

## Errors you might see

| `code` | Meaning |
|---|---|
| `invalid_code` | Wrong, expired, already used, or out of guesses. Ask for a new one. |
| `password_too_short` | Below the instance's minimum (8 by default). The code is **not** used up, so the user can retry. |
| `rate_limited` | Too many attempts. Wait and try again. |
