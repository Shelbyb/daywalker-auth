---
title: Build your own sign-in form
description: Use your own design instead of the hosted pages.
---

The hosted pages are the quickest option. To keep users on your own domain with your own design, call the SDK directly. Security is the same either way.

## Before you start

Add your app's origin to the instance's **allowed origins**. The service rejects sign-in requests from origins it doesn't know, which stops other sites from submitting forms on your users' behalf.

```bash
npm run seed -- https://app.example.com
```

## Sign-in form

```tsx
"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";
import { useAuth, AuthError } from "@daywalker/auth/react";

export function SignInForm() {
  const { signIn } = useAuth();
  const router = useRouter();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError("");
    const f = new FormData(e.currentTarget);
    try {
      await signIn({ email: f.get("email") as string, password: f.get("password") as string });
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof AuthError ? err.message : "Network error, try again");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={onSubmit}>
      <label>Email <input name="email" type="email" autoComplete="email" required /></label>
      <label>Password <input name="password" type="password" autoComplete="current-password" required /></label>
      {error && <p role="alert">{error}</p>}
      <button disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>
    </form>
  );
}
```

Some things to get right:

- **`autoComplete` attributes** let password managers fill and save credentials.
- **Show `err.message` as-is.** It's written for end users. On a wrong password it deliberately doesn't say whether the email exists.
- **Disable the button while busy** to avoid double submissions.

## Sign-up form

The same idea with `signUp`. Show field-level problems from `err.fields`:

```tsx
try {
  await signUp({ email, password, firstName, lastName });
} catch (err) {
  if (err instanceof AuthError) {
    // e.g. [{ path: "email", message: "Invalid email address" }]
    for (const f of err.fields) showFieldError(f.path, f.message);
    if (err.code === "email_taken") showFieldError("email", err.message);
  }
}
```

Then send new users through [email verification](/docs/guides/email-verification).

## Sign out

```tsx
const { signOut } = useAuth();
await signOut(); // ends the session on the server and in every open tab
```
