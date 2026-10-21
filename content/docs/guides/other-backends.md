---
title: Express, Hono and other servers
description: Verify session tokens in any JavaScript server.
---

`@daywalker/auth/server` works in Node.js, Bun, Deno and edge runtimes. You need two values:

```bash
DAYWALKER_PUBLISHABLE_KEY=pk_test_...
DAYWALKER_AUTH_URL=https://auth.daywalker.dev
```

## Express

```ts
import express from "express";
import { verifyToken } from "@daywalker/auth/server";

const app = express();

async function requireAuth(req, res, next) {
  const token = req.headers.authorization?.replace(/^Bearer /, "");
  const session = await verifyToken(token, {
    publishableKey: process.env.DAYWALKER_PUBLISHABLE_KEY!,
    frontendApi: process.env.DAYWALKER_AUTH_URL!,
    authorizedParties: ["https://app.example.com"], // where your frontend runs
  });
  if (!session) return res.status(401).json({ error: "Not signed in" });
  req.userId = session.userId;
  next();
}

app.get("/notes", requireAuth, async (req, res) => {
  res.json(await db.notes.findMany({ where: { ownerId: req.userId } }));
});
```

## Hono

```ts
import { Hono } from "hono";
import { verifyToken } from "@daywalker/auth/server";

const app = new Hono<{ Variables: { userId: string } }>();

app.use("/api/*", async (c, next) => {
  const session = await verifyToken(c.req.header("authorization")?.slice(7), {
    publishableKey: c.env.DAYWALKER_PUBLISHABLE_KEY,
    frontendApi: c.env.DAYWALKER_AUTH_URL,
  });
  if (!session) return c.json({ error: "Not signed in" }, 401);
  c.set("userId", session.userId);
  await next();
});
```

## NestJS guard

```ts
import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from "@nestjs/common";
import { verifyToken } from "@daywalker/auth/server";

@Injectable()
export class AuthGuard implements CanActivate {
  async canActivate(ctx: ExecutionContext) {
    const req = ctx.switchToHttp().getRequest();
    const session = await verifyToken(req.headers.authorization?.slice(7), {
      publishableKey: process.env.DAYWALKER_PUBLISHABLE_KEY!,
      frontendApi: process.env.DAYWALKER_AUTH_URL!,
    });
    if (!session) throw new UnauthorizedException();
    req.userId = session.userId;
    return true;
  }
}
```

## About `verifyToken`

- It returns `null` for any bad, expired or foreign token, so a simple `if (!session)` is enough.
- It **throws** if the public keys can't be fetched (for example, the auth service is unreachable). That way an outage shows up as an error, not as everyone silently being signed out.
- **`authorizedParties` is optional but recommended.** It rejects tokens issued to a different app on the same instance.

## Other languages

Session tokens are standard ES256 JWTs. Any JWT library can verify them. Use these settings:

- **JWKS URL:** `<auth url>/i/<instance id>/.well-known/jwks.json`
- **Issuer:** `<auth url>/i/<instance id>`
- **Algorithm:** `ES256` only. Reject everything else.
- **Required claims:** `sub` (user ID), `sid` (session ID), `exp`, `iat`

For the issuer, the instance ID is encoded inside your publishable key. In JavaScript, `instanceIdFromKey(pk)` from `@daywalker/auth` decodes it.
