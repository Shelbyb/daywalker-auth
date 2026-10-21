---
title: Read the current user
description: Get the signed-in user's ID, email and profile on the client and the server.
---

## On the client

`useUser()` returns the user's profile. `useAuth()` returns IDs and actions.

```tsx
"use client";
import { useUser, useAuth } from "@daywalker/auth/react";

export function Greeting() {
  const { isLoaded, user } = useUser();
  const { isSignedIn } = useAuth();

  if (!isLoaded) return <p>Loading…</p>;   // first render, before the session is known
  if (!isSignedIn) return <p>Hello, stranger.</p>;

  const email = user!.emailAddresses.find((e) => e.primary)?.email;
  return <p>Hello, {user!.firstName ?? email}!</p>;
}
```

Always check `isLoaded` first. On the very first render the SDK hasn't asked the server yet, so the user is unknown, which is not the same as signed out.

The `user` object looks like this:

```json
{
  "id": "user_2x8k…",
  "firstName": "Ada",
  "lastName": "Lovelace",
  "imageUrl": null,
  "emailAddresses": [
    { "id": "email_9f…", "email": "ada@example.com", "primary": true, "verified": true }
  ],
  "publicMetadata": {},
  "lastSignInAt": "2026-10-21T20:15:00.000Z",
  "createdAt": "2026-10-01T12:00:00.000Z"
}
```

## On the server

`auth()` gives you the IDs instantly from the session token, with no network call:

```ts
import { auth } from "@daywalker/auth/nextjs";

const { isSignedIn, userId, sessionId } = await auth();
```

For profile details, fetch the user with the backend API:

```tsx
// app/account/page.tsx
import { Suspense } from "react";
import { auth, backend } from "@daywalker/auth/nextjs";

export default async function Account() {
  const { userId } = await auth();
  if (!userId) return null;
  return (
    <main>
      <h1>Your account</h1>
      {/* The heading shows immediately; the profile streams in when ready */}
      <Suspense fallback={<p>Loading profile…</p>}>
        <Profile userId={userId} />
      </Suspense>
    </main>
  );
}

async function Profile({ userId }: { userId: string }) {
  const user = await backend().users.get(userId);
  return <p>{user.emailAddresses[0].email}</p>;
}
```

> **Tip** Use `userId` as the foreign key in your own database (e.g. `orders.owner_id`). It never changes, unlike email addresses.

## Public and private metadata

| Field | Visible to | Use it for |
|---|---|---|
| `publicMetadata` | The user's browser and your server | Non-sensitive data your UI needs, like a plan name |
| `privateMetadata` | Your server only (backend API). Encrypted at rest. | Internal IDs, such as a billing customer ID |
