---
title: Call your own API
description: Send the session token from the browser so your API knows who's calling.
---

When a client component calls your API, the API needs proof of who's calling. That proof is the session token.

## Same-origin Next.js routes: nothing to do

If your API is a Route Handler in the same Next.js app, the SDK already sends the token in the `__dw_session` cookie, so plain `fetch` works:

```tsx
"use client";
const res = await fetch("/api/notes"); // auth() in the route sees the user
```

## Any API: use `authFetch`

`authFetch` is `fetch` that adds `Authorization: Bearer <token>`, refreshing the token first if needed. Use it for APIs on another domain, or whenever you want to be explicit:

```tsx
"use client";
import { useAuth } from "@daywalker/auth/react";

export function SaveButton({ text }: { text: string }) {
  const { authFetch } = useAuth();

  async function save() {
    const res = await authFetch("https://api.example.com/notes", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
    });
    if (!res.ok) alert("Could not save");
  }

  return <button onClick={save}>Save</button>;
}
```

## Getting the raw token

For WebSockets, GraphQL clients or anything that isn't `fetch`, ask for the token directly:

```ts
const { getToken } = useAuth();
const token = await getToken(); // null when signed out

const ws = new WebSocket(`wss://realtime.example.com?token=${token}`);
```

`getToken()` is cheap: it returns the cached token unless it's about to expire, and simultaneous calls share one refresh.

> **Warning** Don't store the token in `localStorage` or log it. Call `getToken()` each time you need one. It's only valid for 60 seconds anyway.

## Verifying on the receiving end

- **Next.js:** `auth()` reads either the cookie or the `Authorization` header.
- **Anything else:** see [Express, Hono and other servers](/docs/guides/other-backends).
