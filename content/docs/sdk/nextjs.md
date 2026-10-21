---
title: "@daywalker/auth/nextjs"
description: Server helpers for the Next.js App Router.
---

## Environment variables

| Variable | Required | Notes |
|---|---|---|
| `NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY` | yes | `pk_test_…` / `pk_live_…` |
| `NEXT_PUBLIC_DAYWALKER_AUTH_URL` | yes | e.g. `https://auth.daywalker.dev` |
| `DAYWALKER_SECRET_KEY` | for `backend()` | `sk_…`. Never prefix with `NEXT_PUBLIC_`. |
| `DAYWALKER_AUTHORIZED_PARTIES` | no | Comma-separated origins allowed to have minted tokens (`azp`) |

## `auth()`

```ts
const session = await auth();
// { isSignedIn: true, userId, sessionId, issuedAt, expiresAt, azp? }
// { isSignedIn: false, userId: null, sessionId: null }
```

- Works in Server Components, Route Handlers and Server Actions.
- Reads the token from `Authorization: Bearer …` or the `__dw_session` cookie, and verifies it locally.
- Because it reads request headers, pages that call it render dynamically.

## `authProxy(options)`

Returns a function to export from `proxy.ts` (Next 16) or `middleware.ts` (Next 15).

| Option | Type | Description |
|---|---|---|
| `protect` | `(string \| RegExp)[]` | Routes that need a session. A trailing `*` means "this prefix". |
| `signInUrl` | `string?` | Where to send signed-out page visits. Default: the hosted sign-in page. |

```ts
export default authProxy({ protect: ["/dashboard*", "/api/private*"] });
export const config = { matcher: ["/((?!_next|favicon.ico).*)"] };
```

See [Protect pages and APIs](/docs/guides/protect-routes) for the behaviour in detail.

## `backend()`

A [backend client](/docs/sdk/server#createbackendclient-options) configured from `DAYWALKER_SECRET_KEY`:

```ts
const user = await backend().users.get(userId);
```
