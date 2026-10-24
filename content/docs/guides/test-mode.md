---
title: Test mode and end-to-end tests
description: Sign in to a development instance in automated tests with a fixed code, no mailbox and no phone.
---

# Test mode and end-to-end tests

Email codes and texted codes make browser tests painful. **Test mode** gives development instances addresses and phone numbers that always accept one code:

| | |
|---|---|
| Code | `424242` |
| Email | any address with the tag `+daywalker_test`, like `alice+daywalker_test@example.com` |
| Phone | the reserved numbers `+1 555 555 0100` to `+1 555 555 0199` |

No email or text is sent to them. Everything else behaves as usual, including the attempt limits (5 wrong tries burn a code) and the per-address send limits. Real addresses and numbers are untouched.

## Turn it on

**Dashboard → Configure → Developers → Environments → Test mode** on a development instance, or:

```ts
await backend().testMode.set(true);   // PATCH /v1/instance/test_mode { "enabled": true }
```

It is off by default. Don't leave it on for an instance real people use: anyone who knows the code can sign in to a test address. With it on, the components show "Development mode, test mode on" so it is never silent.

## It never works on production

- Production instances can't turn it on (`403 test_mode_unavailable`), and a stored flag is ignored.
- On production, signing up with, or requesting a code for, a `+daywalker_test` address fails with `400 test_mode_unavailable`, and a reserved phone number with `400 test_phone_unavailable`. The messages say it is for development instances.
- With test mode off on a development instance, reserved phone numbers are refused too (there is nobody to text); test email addresses are ordinary addresses.
- [Cloning configuration](/docs/guides/environments) to production never copies it (the clone reports it under `skipped`).
- The platform's own dashboard instance never honors it.
- A test address is never proof of a company domain: organization domain auto-join and suggestions ignore it.

## Writing a test

Helpers are in `@daywalker/auth/server` (and the browser entry point):

```ts
import { testEmail, testPhone, TEST_CODE } from "@daywalker/auth/server";

const email = testEmail("alice", { unique: true });   // alice.k3j9x2ab+daywalker_test@example.com
const phone = testPhone(7);                           // +15555550107
```

Playwright, passwordless sign-in with the components or hosted page:

```ts
test("signs in with a code", async ({ page }) => {
  await page.goto("/sign-in");
  await page.getByLabel("Email").fill(email);
  await page.getByRole("button", { name: /email me a code/i }).click();
  await page.getByLabel("Code").fill(TEST_CODE);
  await page.getByRole("button", { name: /verify|continue/i }).click();
  await expect(page).toHaveURL(/dashboard/);
});
```

Sign-up with a password, then verification, password reset and the SMS second factor all take `424242` in the code field. To skip the UI for set-up, create the user from your test runner with the browser client or your backend and sign in through the page.

Tips:

- Use a **unique address per run** (`unique: true`) so tests don't share accounts or hit the per-address send limit (5 per hour).
- Clean up with `backend().users.delete(id)`; test users are ordinary users of the development instance.
- Run your tests against the development instance's keys (`pk_test_…`, `sk_test_…`), never production keys.
- For session tokens in API tests, sign in once in `globalSetup` and reuse the cookies.
- For service-to-service tests use [machine clients](/docs/guides/machine-auth) instead of a user.

Errors: `test_mode_unavailable` (400 on sign-up or sending a code, 403 when enabling), `test_phone_unavailable` (400).
