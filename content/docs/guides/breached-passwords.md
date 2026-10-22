---
title: Breached passwords
description: Stop people from choosing passwords that have already leaked.
---

# Breached passwords

Passwords that showed up in an earlier data breach are the first ones attackers try. Daywalker checks every **new** password against the [Pwned Passwords](https://haveibeenpwned.com/Passwords) database of over a billion leaked passwords, and rejects any match.

It's **on by default** for every instance. You can turn it off in the dashboard under **Settings → Block breached passwords**.

## When it runs

- Sign-up
- Changing a password on the account page
- Resetting a forgotten password (checked before the reset code is used, so the user can try again with the same code)

It doesn't run at sign-in, so nobody is locked out of an existing account.

When a password is rejected, the API returns `400` with the code `password_breached`. The hosted pages show the message, and the SDK raises an `AuthError` with that code:

```ts
try {
  await auth.signUp({ email, password });
} catch (e) {
  if (e instanceof AuthError && e.code === "password_breached") showHint("Pick a password you haven't used anywhere else.");
}
```

## Privacy

The password never leaves your server. The check uses **k-anonymity**:

1. Daywalker hashes the password with SHA-1.
2. It sends only the **first 5 characters** of that hash to the Pwned Passwords API.
3. The API returns every leaked hash starting with those 5 characters, padded with fake entries so the response size gives nothing away.
4. Daywalker looks for the rest of the hash in that list, on its own server.

Hundreds of unrelated passwords share any 5-character prefix, so the API can't tell which password you checked.

## If the service is unreachable

The check gives up after 2.5 seconds, accepts the password, and logs a warning. An outage elsewhere never stops people from signing up. Your other rules, such as the minimum length, still apply.
