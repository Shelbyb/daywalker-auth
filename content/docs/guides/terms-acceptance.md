---
title: Require terms at sign-up
description: Make new users accept your terms of service and privacy policy, and keep a record that they did.
---

Many apps need proof that each user agreed to their terms. Turn this on, and every **new** account must tick an "I agree" box before it can be created, whether they sign up with email or with Google/GitHub. Each acceptance is saved with the terms **version** and the time.

> **Note** This is about **your app's** terms with **your users**. Daywalker Auth's own [Terms of Service](/docs/legal/terms) cover the relationship between you and the platform.

## 1. Publish your terms

Host your terms of service, and ideally a privacy policy, at stable URLs, e.g. `https://example.com/terms` and `https://example.com/privacy`.

## 2. Turn on required acceptance

Call the backend API with your secret key:

```bash
curl -X PUT https://users.example.com/v1/instance/legal \
  -H "Authorization: Bearer $DAYWALKER_SECRET_KEY" \
  -H "content-type: application/json" \
  -d '{
    "required": true,
    "termsUrl": "https://example.com/terms",
    "privacyUrl": "https://example.com/privacy",
    "version": "2026-10-21"
  }'
```

| Field | Meaning |
|---|---|
| `required` | `true`: new users must accept before an account is created |
| `termsUrl` | Your terms page (HTTPS). Required when `required` is `true`. |
| `privacyUrl` | Optional privacy policy page |
| `version` | Any label for this edition of your terms, such as a date. **Change it whenever your terms change.** |

## 3. What users see

**Hosted pages:** the sign-up page shows a checkbox linking to your terms and privacy policy.

- It starts unticked.
- The **Create account** button and the **Continue with Google/GitHub** buttons stay disabled until it's ticked.
- If someone uses Google/GitHub from the sign-in page and it would create a new account without consent, they're sent to the sign-up page to tick the box.

**Your own UI:** read the settings, show your own checkbox, and pass the user's choice:

```tsx
"use client";
import { useEffect, useState } from "react";
import { useAuth, useAuthClient } from "@daywalker/auth/react";

export function SignUpForm() {
  const client = useAuthClient();
  const { signUp, signInWithOAuth } = useAuth();
  const [legal, setLegal] = useState<{ required: boolean; termsUrl: string | null } | null>(null);
  const [accepted, setAccepted] = useState(false);
  useEffect(() => { client.getEnvironment().then((e) => setLegal(e.legal)); }, [client]);

  const blocked = !!legal?.required && !accepted;

  return (
    <form onSubmit={async (e) => {
      e.preventDefault();
      const f = new FormData(e.currentTarget);
      await signUp({ email: f.get("email") as string, password: f.get("password") as string, legalAccepted: accepted });
    }}>
      <input name="email" type="email" required />
      <input name="password" type="password" required />
      {legal?.required && (
        <label>
          <input type="checkbox" checked={accepted} onChange={(e) => setAccepted(e.target.checked)} />
          I agree to the <a href={legal.termsUrl!} target="_blank" rel="noopener noreferrer">Terms of Service</a>
        </label>
      )}
      <button disabled={blocked}>Create account</button>
      <button type="button" disabled={blocked} onClick={() => signInWithOAuth("google", undefined, { legalAccepted: accepted })}>
        Continue with Google
      </button>
    </form>
  );
}
```

If you forget to pass `legalAccepted: true`, sign-up fails with `legal_required`. The server enforces the rule; the checkbox alone isn't trusted.

## Who has to accept

| Situation | Must accept? |
|---|---|
| New account with email and password | Yes |
| New account through Google/GitHub | Yes |
| Existing user signing in, by any method | No |
| Existing user whose email gets linked to Google/GitHub | No (already a user) |

## Records

Each acceptance stores the user, the `version` in force, the method (`password`, `google` or `github`) and the time. It's removed if the user is deleted. Asking existing users to re-accept when you publish a new version is on the roadmap. For now, bumping `version` affects new sign-ups only.

## Good practice

- **Never pre-tick the box.** In many places, consent only counts if it's an active choice. The hosted page never pre-ticks it.
- **Keep old versions of your terms** available somewhere, so a recorded version can be matched to the exact text the user agreed to.
- **Turning `required` off** stops requiring acceptance for new users; existing records are kept.
