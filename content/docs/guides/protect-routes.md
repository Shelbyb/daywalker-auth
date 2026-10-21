---
title: Protect pages and APIs
description: Decide which routes require a signed-in user, and what happens when there isn't one.
---

There are three layers of protection. You'll usually use the first, and sometimes add the others.

| Layer | Where | Good for |
|---|---|---|
| `authProxy` | `proxy.ts` / `middleware.ts` | Whole sections of your site (e.g. everything under `/dashboard`) |
| `auth()` | Server Components, Route Handlers, Server Actions | Per-route checks and getting the `userId` |
| `<SignedIn>` / `<SignedOut>` | Client components | Showing or hiding UI. **Not a security boundary.** |

## Protect sections with `authProxy`

```ts
// proxy.ts
import { authProxy } from "@daywalker/auth/nextjs";

export default authProxy({
  protect: [
    "/dashboard*",          // /dashboard and everything below it
    "/settings",            // exactly /settings
    /^\/projects\/[^/]+\/edit$/, // regular expressions work too
    "/api/private*",
  ],
});

export const config = { matcher: ["/((?!_next|favicon.ico).*)"] };
```

Matching rules:

- A string ending in `*` matches that prefix.
- Any other string must match the path exactly.
- A `RegExp` is tested against the path, without the query string.

What happens to signed-out requests:

- **Page requests** are redirected to the hosted sign-in page, with a `redirect_url` that brings the user back.
- **API requests** get `401` with a JSON body. A request counts as an API request if its path starts with `/api` or it sends `Accept: application/json`.

### Using your own sign-in page

If you built your own form (see [Build your own sign-in form](/docs/guides/custom-ui)), point the proxy at it:

```ts
export default authProxy({ protect: ["/dashboard*"], signInUrl: "https://app.example.com/login" });
```

## Check inside a route with `auth()`

Even with the proxy in place, **always check `auth()` in API routes and Server Actions that change data.** It's cheap, and it keeps the route safe if someone later edits the proxy's list.

```ts
// app/api/notes/route.ts
import { auth } from "@daywalker/auth/nextjs";

export async function POST(req: Request) {
  const { userId } = await auth();
  if (!userId) return Response.json({ error: "Not signed in" }, { status: 401 });

  const { text } = await req.json();
  const note = await db.notes.create({ ownerId: userId, text });
  return Response.json(note, { status: 201 });
}
```

```ts
// app/notes/actions.ts
"use server";
import { auth } from "@daywalker/auth/nextjs";

export async function deleteNote(noteId: string) {
  const { userId } = await auth();
  if (!userId) throw new Error("Not signed in");
  // Scope by owner, so users can't delete each other's notes by guessing IDs
  await db.notes.delete({ where: { id: noteId, ownerId: userId } });
}
```

> **Warning** Checking that someone is signed in is **authentication**. You still need **authorization**: checking that *this* user may touch *this* record. Always scope database queries by `userId`, as above.

## Hide UI on the client

```tsx
"use client";
import { SignedIn, SignedOut } from "@daywalker/auth/react";

export function Pricing() {
  return (
    <>
      <SignedOut><a href="/sign-up">Start free</a></SignedOut>
      <SignedIn><a href="/dashboard">Go to your dashboard</a></SignedIn>
    </>
  );
}
```

Client-side checks only change what's shown. Anyone can edit JavaScript in their browser, so never rely on them to protect data. That's what the server checks above are for.
