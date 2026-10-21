---
title: Manage users from your server
description: List, look up and delete users, and sign people out remotely.
---

The backend client uses your **secret key**, so use it only in server code.

```ts
// Next.js: configured from env automatically
import { backend } from "@daywalker/auth/nextjs";
const api = backend();

// Anywhere else
import { createBackendClient } from "@daywalker/auth/server";
const api = createBackendClient({ secretKey: process.env.DAYWALKER_SECRET_KEY!, apiUrl: "https://users.daywalker.dev" });
```

## List users

```ts
const firstPage = await api.users.list({ limit: 20 });
const secondPage = await api.users.list({ limit: 20, offset: 20 });
```

Newest first. `limit` is 1–100.

## Get one user

```ts
const user = await api.users.get("user_2x8k…");
console.log(user.emailAddresses[0].email, user.privateMetadata);
```

## Delete a user

```ts
await api.users.delete("user_2x8k…");
```

This removes the user, their email addresses, password and sessions. Their current session token stops being refreshable straight away. It can't be undone, so remove the user's data from your own database too.

## Sign a user out remotely

```ts
await api.sessions.revoke("sess_7h2…");
```

The session can't mint new tokens, so the user is signed out within 60 seconds on that device. `auth()` gives you the current `sessionId` if you want to show a "sign out of this device" button.

## Handling errors

```ts
import { BackendError } from "@daywalker/auth/server";

try {
  await api.users.get(id);
} catch (e) {
  if (e instanceof BackendError && e.status === 404) return notFound();
  throw e;
}
```
