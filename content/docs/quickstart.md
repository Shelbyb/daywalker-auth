---
title: "Quickstart: Next.js"
description: Protect a Next.js app with sign-in in about 10 minutes.
---

By the end of this page you'll have:

- a Next.js app with **Sign in** and **Sign up** buttons
- a `/dashboard` page only signed-in users can open
- an API route that knows who is calling it

> **Note** This guide assumes Next.js 15 or 16 with the App Router (the `app/` directory). Using something else? See [Express, Hono and other servers](/docs/guides/other-backends).

## 1. Get your keys

Every app gets an **instance** with two keys. If you're running Daywalker Auth yourself, create one from the service folder and pass your app's URL so the service accepts requests from it:

```bash
npm run seed -- http://localhost:3001
```

```text
Instance:        ins_…
Publishable key: pk_test_…
Secret key:      sk_test_…   (shown once; store it in your secrets manager)
```

> **Warning** The secret key is only shown once. Copy it now. If you lose it, create a new one.

## 2. Install the SDK

```bash
npm install @daywalker/auth
```

## 3. Add your environment variables

Create `.env.local` in the root of your Next.js app:

```bash
NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY=pk_test_...
NEXT_PUBLIC_DAYWALKER_AUTH_URL=http://localhost:3000
DAYWALKER_SECRET_KEY=sk_test_...
```

- Variables starting with `NEXT_PUBLIC_` are bundled into browser code. That's fine for the publishable key and URL.
- `DAYWALKER_SECRET_KEY` has **no** prefix on purpose. Next.js keeps it on the server.

> **Warning** Never rename it to `NEXT_PUBLIC_DAYWALKER_SECRET_KEY`. That would publish your secret key to every visitor.

## 4. Wrap your app in `<AuthProvider>`

`AuthProvider` loads the current session and keeps it fresh. Every auth component and hook must be inside it, so put it in your root layout:

```tsx
// app/layout.tsx
import { AuthProvider } from "@daywalker/auth/react";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
```

## 5. Add sign-in and user buttons

```tsx
// app/header.tsx
"use client";

import { SignedIn, SignedOut, SignInButton, UserButton } from "@daywalker/auth/react";

export function Header() {
  return (
    <header>
      <SignedOut>
        <SignInButton />
        <SignInButton mode="sign-up">Create account</SignInButton>
      </SignedOut>
      <SignedIn>
        <UserButton afterSignOutUrl="/" />
      </SignedIn>
    </header>
  );
}
```

- `<SignedOut>` and `<SignedIn>` show their children only in that state.
- `<SignInButton>` sends the user to the hosted sign-in page and brings them back to the same page afterwards.
- `<UserButton>` shows the user's initials and a menu with **Sign out**.

Render `<Header />` from your layout or a page. Run `npm run dev` and try signing up.

## 6. Protect pages and API routes

Create `proxy.ts` next to your `app/` folder. It's named `middleware.ts` on Next.js 15.

```ts
// proxy.ts
import { authProxy } from "@daywalker/auth/nextjs";

export default authProxy({ protect: ["/dashboard*", "/api/private*"] });

export const config = { matcher: ["/((?!_next|favicon.ico).*)"] };
```

- `"/dashboard*"` matches `/dashboard` and everything under it.
- A signed-out visitor to a protected **page** is redirected to sign-in, then returned.
- A signed-out request to a protected **API route** (anything under `/api`) gets `401 Unauthorized`.

## 7. Use the user on the server

`auth()` works in Server Components, Route Handlers and Server Actions:

```tsx
// app/dashboard/page.tsx
import { auth, backend } from "@daywalker/auth/nextjs";

export default async function Dashboard() {
  const { userId } = await auth();
  if (!userId) return null; // proxy.ts already redirects signed-out users

  const user = await backend().users.get(userId);
  return <h1>Welcome, {user.firstName ?? user.emailAddresses[0].email}</h1>;
}
```

```ts
// app/api/private/orders/route.ts
import { auth } from "@daywalker/auth/nextjs";

export async function GET() {
  const { userId } = await auth();
  if (!userId) return Response.json({ error: "Not signed in" }, { status: 401 });
  return Response.json({ orders: await getOrdersFor(userId) });
}
```

## You're done

Sign in, open `/dashboard`, then sign out and try again. You'll be sent to sign in first.

**Next steps**

- [How it works](/docs/how-it-works): what happens behind the scenes.
- [Call your own API](/docs/guides/call-your-api): send the session token from client components.
- [Email verification](/docs/guides/email-verification): require a confirmed email.
