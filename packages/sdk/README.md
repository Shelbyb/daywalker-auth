# @daywalker/auth

SDK for Daywalker Auth. One package, four entry points:

| Import | Runs in | Use for |
|---|---|---|
| `@daywalker/auth` | browser | `createAuthClient`: sign in/up/out, tokens, `authFetch` |
| `@daywalker/auth/react` | client components | `<AuthProvider>`, `useAuth`, `useUser`, `<SignedIn>`, `<SignedOut>`, `<SignInButton>`, `<SignOutButton>`, `<UserButton>` |
| `@daywalker/auth/server` | Node / edge | `verifyToken`, `createBackendClient` |
| `@daywalker/auth/nextjs` | Next.js server | `authProxy` (route protection), `auth()`, `backend()` |

A complete working app is in [`examples/nextjs`](../../examples/nextjs).

## Next.js quick start

**1. Environment** (`.env.local`)

```bash
NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY=pk_test_...
NEXT_PUBLIC_DAYWALKER_AUTH_URL=https://users.daywalker.dev
DAYWALKER_SECRET_KEY=sk_test_...                      # server only, never NEXT_PUBLIC_
DAYWALKER_AUTHORIZED_PARTIES=https://app.example.com  # optional, recommended
```

Your app's origin must be on the instance's allowed origins (`npm run seed -- https://app.example.com` in the service repo).

**2. Provider** (`app/layout.tsx`)

```tsx
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

**3. Protect routes** (`src/proxy.ts`, or `middleware.ts` on Next 15)

```ts
import { authProxy } from "@daywalker/auth/nextjs";

export default authProxy({ protect: ["/dashboard*", "/api/private*"] });
export const config = { matcher: ["/((?!_next|favicon.ico).*)"] };
```

Signed-out page visits go to the hosted sign-in page and return afterwards; API routes get a 401.

**4. Use the session**

```tsx
// Client component
"use client";
import { SignedIn, SignedOut, SignInButton, UserButton, useAuth } from "@daywalker/auth/react";

export function Header() {
  const { authFetch } = useAuth(); // fetch with Authorization: Bearer <jwt>
  return (
    <>
      <SignedOut><SignInButton /></SignedOut>
      <SignedIn><UserButton afterSignOutUrl="/" /></SignedIn>
    </>
  );
}
```

```ts
// Server Component, Route Handler or Server Action
import { auth, backend } from "@daywalker/auth/nextjs";

const session = await auth();
if (session.isSignedIn) {
  const user = await backend().users.get(session.userId);
}
```

## Other frameworks

```ts
// Browser
import { createAuthClient } from "@daywalker/auth";
const client = createAuthClient({ publishableKey, frontendApi: "https://users.daywalker.dev" });
await client.load();
await client.signIn({ email, password });
// Or passwordless (turn on "Email sign-in" in the dashboard):
// await client.sendSignInCode({ email }); await client.signInWithEmailCode({ email, code });
const res = await client.authFetch("/api/orders");

// Any Node/edge server (Express, Hono, NestJS guard…)
import { verifyToken } from "@daywalker/auth/server";
const session = await verifyToken(req.headers.authorization?.slice(7), {
  publishableKey, frontendApi: "https://users.daywalker.dev", authorizedParties: ["https://app.example.com"],
});
if (!session) return res.status(401).end();
```

## Organizations, webhooks and the dashboard

- **Organizations:** `auth()` and `verifyToken()` return `orgId` and `orgRole` when the user has an active organization. In the browser, `createOrganization`, `inviteToOrg`, `setActiveOrganization` and friends are on the client. See `/docs/guides/organizations`.
- **Webhooks:** `verifyWebhook(rawBody, headers, secret)` from `@daywalker/auth/server` checks the signature and rejects replays; `createBackendClient(...).webhooks` manages endpoints. See `/docs/guides/webhooks`.
- **Dashboard:** create instances and copy keys at `/dashboard` on your service. See `/docs/guides/dashboard`.
- **Several instances in one app:** `auth({ config })` and `authProxy({ config })` accept an explicit config instead of the `NEXT_PUBLIC_DAYWALKER_*` env vars.

## How it stays secure

- **Refresh token:** HttpOnly cookie on the auth service; no JavaScript, including yours, can read it.
- **Session JWT:** kept in memory, never in localStorage. It's refreshed 10 s before its 60 s expiry, only in visible tabs, and concurrent callers share one request.
- **`__dw_session` cookie:** the SDK mirrors the JWT into this cookie on your domain so server rendering can authenticate. It's a 60-second credential, `SameSite=Lax`, and `Secure` on HTTPS.
- **`__dw_active` cookie:** a non-secret flag meaning "a session may exist". It lets `authProxy` refresh an expired token in the browser instead of bouncing a returning user to sign-in.
- **`verifyToken`:**
  - Pins `ES256`, so `alg: none` and algorithm-confusion attacks fail.
  - Checks issuer, expiry and required claims, and optionally `azp` against your authorized parties.
  - Returns `null` for bad tokens, but lets JWKS outages throw so they aren't mistaken for "signed out".
- **JWKS:** cached, and refetched automatically on unknown key IDs, so key rotation needs no deploy.
- **Server-only code:** `/server` throws if bundled for the browser, and `createBackendClient` refuses anything that isn't an `sk_` key.
- **Sign-out:** propagates to other open tabs via `BroadcastChannel`.

**If your app sets a strict CSP:** `authProxy` serves a short inline-script page to refresh expired tokens. Allow it with `'unsafe-inline'` scoped to that response, or turn the refresh off by not setting `__dw_active`. Nonce support is planned.

## Splitting into its own repo
The package currently exports TypeScript source and consumers use `transpilePackages: ["@daywalker/auth"]`. Before publishing, add a build step (e.g. tsup to ESM + `.d.ts`), point `exports` at `dist/`, and drop `transpilePackages` from consumers.
