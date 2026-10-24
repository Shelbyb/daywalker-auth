---
title: Webhooks
description: Get a signed HTTP request on your server whenever something happens, like a new sign-up, so you can sync data, send a welcome email or update your own database.
---

A **webhook** is a URL on *your* server that we call when an event happens. Instead of asking us "has anyone signed up?" every few minutes, we tell you the moment it happens.

Typical uses:

- Create a row in your own `profiles` table when `user.created` arrives.
- Send a welcome email.
- Clean up data when `user.deleted` arrives.
- Keep an audit log of sign-ins (`session.created`).

## 1. Write the receiver

Your receiver is a normal route that **verifies the signature first** and only then trusts the data. Anyone can POST to a public URL, so the signature is what proves the request came from us.

```ts
// Next.js: app/api/webhooks/daywalker/route.ts
import { verifyWebhook, WebhookVerificationError } from "@daywalker/auth/server";

export async function POST(req: Request) {
  const rawBody = await req.text(); // the RAW text, not req.json()

  let event;
  try {
    event = verifyWebhook(rawBody, req.headers, process.env.DAYWALKER_WEBHOOK_SECRET!);
  } catch (e) {
    if (e instanceof WebhookVerificationError) return new Response("Bad signature", { status: 400 });
    throw e;
  }

  switch (event.type) {
    case "user.created":
      await db.profiles.insert({ userId: event.data.userId as string, email: event.data.email as string });
      break;
    case "user.deleted":
      await db.profiles.delete({ userId: event.data.userId as string });
      break;
  }

  return new Response("ok"); // any 2xx means "received"
}
```

> **Use the raw body.** The signature covers the exact bytes we sent. If you parse the JSON and re-serialize it, the signature won't match.

Respond with a `2xx` quickly (within 10 seconds). Do slow work in a background job.

## 2. Register the endpoint

Do this once, from a script or your server (it needs your secret key):

```ts
import { createBackendClient } from "@daywalker/auth/server";

const api = createBackendClient({ secretKey: process.env.DAYWALKER_SECRET_KEY!, apiUrl: "https://users.daywalker.dev" });

const endpoint = await api.webhooks.create({
  url: "https://myapp.com/api/webhooks/daywalker",
  events: ["user.created", "user.deleted"], // omit to receive everything
  description: "Sync profiles",
});

console.log(endpoint.secret); // whsec_...  save this now!
```

**The signing secret is shown only once.** Put it in your environment as `DAYWALKER_WEBHOOK_SECRET`. If you lose it, rotate it (below).

Then send yourself a test event to check everything works:

```ts
await api.webhooks.sendTest(endpoint.id); // you'll receive a "webhook.test" event
```

## Events

| Event | When | `data` |
| --- | --- | --- |
| `user.created` | Someone signs up | `userId`, `email` |
| `user.deleted` | A user is deleted through the backend API | `userId` |
| `user.locked` | An account is locked after repeated failed attempts | `userId`, `lockedUntil`, `level`, `reason` |
| `user.deletion_requested` | A user scheduled their account for deletion | `userId`, `scheduledFor` |
| `user.deletion_canceled` | A pending deletion was canceled (email link or admin) | `userId`, `via` |
| `user.unlocked` | A lockout is lifted (unlock link, admin, password reset) | `userId`, `reason` |
| `session.created` | Someone signs in | `sessionId`, `userId` |
| `session.revoked` | A session is revoked | `sessionId` |
| `organization.created` | An organization is created | `organizationId`, `name`, `slug`, `createdBy` |
| `organization.deleted` | An organization is deleted | `organizationId` |
| `organizationMembership.created` | Someone joins an organization | `organizationId`, `userId`, `role` |
| `organizationMembership.deleted` | Someone is removed or leaves | `organizationId`, `userId` |
| `organizationInvitation.created` | An invitation is sent | `organizationId`, `invitationId`, `email`, `role` |
| `webhook.test` | You send a test | `message` |

Every request body looks like this:

```json
{
  "id": "evt_8h2k...",
  "type": "user.created",
  "createdAt": "2026-10-21T21:50:00.000Z",
  "data": { "userId": "user_abc", "email": "ada@example.com" }
}
```

Use `id` to **ignore duplicates**: we may deliver the same event more than once (for example, if your server processed it but timed out before answering), and retries keep the same `id`.

## How we retry

If your server doesn't answer with a `2xx` (or is down), we try again with growing gaps:

| Attempt | Waits before it |
| --- | --- |
| 2 | about 30 seconds |
| 3 | 2 minutes |
| 4 | 10 minutes |
| 5 | 30 minutes |
| 6 | 1 hour |
| 7 | 3 hours |
| 8 | 6 hours |

After 8 failed attempts (roughly 10 hours) the delivery is marked `failed`. Fix your receiver, then re-queue it:

```ts
const log = await api.webhooks.deliveries(endpoint.id); // status, attempts, last error, next retry
await api.webhooks.retry(log[0].id);
```

The log shows only status codes and short errors. Payloads and your server's responses are never stored in it. Delivery history is deleted after 30 days.

## Manage endpoints

```ts
await api.webhooks.list();
await api.webhooks.update(id, { events: ["*"], enabled: false }); // pause without deleting
await api.webhooks.rotateSecret(id); // the old secret stops working immediately
await api.webhooks.delete(id);
```

You can have up to 10 endpoints. Each can subscribe to different events.

## Security

- **Verify every request.** `verifyWebhook` checks the HMAC signature (using a constant-time comparison) and rejects timestamps more than 5 minutes old, so a captured request can't be replayed later.
- **HTTPS only.** Webhook URLs must use `https://`.
- **No internal addresses.** We refuse to call private or internal addresses (such as `10.x.x.x`, `192.168.x.x`, `127.0.0.1` or cloud metadata endpoints), and we re-check the address at the moment we connect, so a hostname can't be switched to an internal address after registration. We don't follow redirects. This stops webhooks being used to probe a private network.
- **Encrypted at rest.** Endpoint URLs, signing secrets and queued payloads are stored encrypted.
- **Rotate if leaked.** If a secret might be exposed, rotate it right away.

## Testing locally

We can't reach `localhost`, so use a tunnel such as `cloudflared` or `ngrok` to give your dev server a public HTTPS URL, and register that URL for your development instance.

## Verifying without the SDK

The signing scheme follows the open [Standard Webhooks](https://www.standardwebhooks.com) format, so libraries in other languages work too. We send the headers `webhook-id`, `webhook-timestamp` and `webhook-signature`. The signature is `v1,` followed by the base64 HMAC-SHA256 of `{webhook-id}.{webhook-timestamp}.{raw body}`, keyed with the base64-decoded part of your secret after `whsec_`.
