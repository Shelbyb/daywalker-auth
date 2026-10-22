---
title: Email codes and magic links
description: Let people sign in without a password, with a code or a one-time link from their email.
---

# Email codes and magic links

Passwordless sign-in: the user enters their email, and Daywalker sends one email with **a 6-digit code** and **a sign-in link**. Typing the code or clicking the link signs them in. Either one works once, and using one cancels the other.

## Turn it on

In the dashboard, open your instance, then **Settings**, tick **Email sign-in codes and links**, and save. The hosted sign-in page then shows **Email me a sign-in code instead**.

People need an account first (made with sign-up or social sign-in). Two-factor still applies: if the account has it on, the user is asked for their authenticator code after the email step.

## With the SDK

```ts
import { createAuthClient } from "@daywalker/auth";

const auth = createAuthClient({ publishableKey: "pk_test_…", frontendApi: "https://users.daywalker.dev" });

// Step 1: send the email. Optional redirectUrl is where the link lands after sign-in.
await auth.sendSignInCode({ email, redirectUrl: "https://app.example.com/dashboard" });

// Step 2a: the user types the code
const r = await auth.signInWithEmailCode({ email, code });
if (r.status === "needs_second_factor") {
  await auth.completeSecondFactor(totpCode);
}
```

Sign-in links open the hosted page at `/magic-link`, which finishes sign-in and sends the user to your `redirectUrl`. To handle links on your own page instead, read the token from the URL fragment (`#token=…`) and call:

```ts
const r = await auth.signInWithMagicLink(token);
if (r.status === "complete" && r.redirectUrl) location.assign(r.redirectUrl);
```

`redirectUrl` must be on one of your instance's allowed origins, or it's dropped.

## How it's kept safe

- **Short-lived and single-use.** Codes and links expire after 10 minutes and work once. Asking for a new email cancels the old one.
- **Limited guesses.** 5 wrong codes and that email's code and link stop working.
- **Nothing to find out.** The send step answers the same way whether or not the email has an account, and nothing is sent to unknown addresses.
- **Throttled.** At most 5 emails an hour per address, plus per-IP limits.
- **Not stored in the clear.** Only a keyed hash of the code and a SHA-256 of the link token are kept, in Valkey.
- **Safe against link scanners.** The token is in the URL fragment, so it's never sent to a server or written to logs, and the page needs a click. Mail filters that open links can't use it up.
- **Logged.** Sign-ins (with `method: "email_code"` or `"magic_link"`) and wrong codes appear in the [audit log](/docs/guides/audit-logs).

Signing in this way also marks the email address as verified, since the user just proved they can read it.
