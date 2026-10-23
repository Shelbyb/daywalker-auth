---
title: Organizations
description: Let users create teams, invite people by email, and give them roles, like a workspace in Slack or a team in Vercel.
---

An **organization** is a group of users that share something: a workspace, a company account, a team. Each organization has **members**, and every member has a **role**.

| Role | Can do |
| --- | --- |
| `admin` | Rename or delete the organization, invite people, change roles, remove members |
| `member` | See the organization and its members, and leave |

Every organization always has at least one admin: the last admin can't be demoted, removed or leave until someone else is promoted.

## How it works for your users

1. A signed-in user creates an organization and becomes its admin.
2. An admin enters a teammate's email. We email them an **invitation link** (valid for 7 days).
3. The teammate opens the link, signs in or signs up **with that same email address**, and accepts.
4. Anyone with several organizations can switch the **active organization**.

The invitation page is hosted for you at `/accept-invite`, so there's nothing to build.

> **Security note.** An invitation can only be accepted by the invited email address, and only after that address is **verified**. A forwarded or leaked link is useless to anyone else. Re-inviting an address replaces the earlier link.

## Create and list (in the browser)

```tsx
"use client";
import { useAuthClient } from "@daywalker/auth/react";

export function Teams() {
  const auth = useAuthClient();

  async function create() {
    const org = await auth.createOrganization("Acme Inc");
    await auth.setActiveOrganization(org.id); // work inside it right away
  }

  async function invite(orgId: string) {
    await auth.inviteToOrg(orgId, "teammate@example.com", "member");
  }

  return <button onClick={create}>New team</button>;
}
```

All the client methods are listed in the [client reference](/docs/sdk/client).

## Know which organization the user is in (on your server)

When a user has an active organization, their session token carries two extra claims, `org_id` and `org_role`. They're signed, so you can trust them without calling us.

```ts
// Next.js: app/api/projects/route.ts
import { auth } from "@daywalker/auth/nextjs";

export async function GET() {
  const { userId, orgId, orgRole } = await auth();
  if (!userId) return new Response("Unauthorized", { status: 401 });
  if (!orgId) return new Response("Pick an organization first", { status: 400 });

  // Always scope your data by orgId.
  const projects = await db.projects.where({ orgId });
  return Response.json({ projects, canEdit: orgRole === "admin" });
}
```

`verifyToken()` from `@daywalker/auth/server` returns the same `orgId` and `orgRole` fields for other frameworks.

> **Roles can change.** A token lives 60 seconds, and we re-check the user's role whenever one is minted, so a removed member loses access within about a minute. For very sensitive actions, confirm with the backend API.

## Backend API

With your secret key you can list organizations and their members:

```ts
import { createBackendClient } from "@daywalker/auth/server";

const backend = createBackendClient({ secretKey: process.env.DAYWALKER_SECRET_KEY!, apiUrl: process.env.DAYWALKER_API_URL! });

const orgs = await backend.organizations.list();
const members = await backend.organizations.members(orgs[0].id); // [{ userId, role, joinedAt }]
```

Organizations are scoped to your instance: another app's secret key can never see them.

## Requiring two-factor

An organization can require two-step verification for its members: `setOrganizationTwoFactor(orgId, true)` in the browser (admins only, and they need it on themselves first) or `PATCH /v1/organizations/{orgId} { "requireTwoFactor": true }` from your backend. Members without it don't get that organization's claims in their token until they turn it on. See [Requiring 2FA](/docs/guides/two-factor#requiring-2fa).

## Good to know

- Non-members get a `404` for an organization, so its existence isn't revealed.
- Deleting an organization removes its memberships and invitations.
- Invitation emails are sent through your configured mail transport.
