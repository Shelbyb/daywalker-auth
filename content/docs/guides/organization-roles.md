---
title: Roles, permissions and domains
description: Define your own organization roles with permissions, check them in your backend, and let people join by verified email domain.
---

# Roles, permissions and domains

## Custom roles

Every organization has two built-in roles: **admin** and **member**. You can add more for your whole instance (dashboard: **Organizations**, or the backend API). A role has a `key` (`billing_manager`), a name, and a list of permission strings.

```ts
const daywalker = createBackendClient({ secretKey: process.env.DAYWALKER_SECRET_KEY!, apiUrl: "https://users.daywalker.dev" });

await daywalker.organizationRoles.create({
  key: "billing_manager",
  name: "Billing manager",
  permissions: ["org:read", "org:billing:manage"],
});
await daywalker.organizationRoles.update("billing_manager", { permissions: ["org:read", "org:billing:read"] });
await daywalker.organizationRoles.delete("billing_manager"); // 409 role_in_use while anyone, an invitation or a setting still uses it
```

- **Permission strings** have two or three lowercase segments: `org:billing:manage`, `reports:export`. Up to 25 per role, 60 different custom permissions per instance (they travel in the token), 20 custom roles.
- **System permissions** control the organization itself: `org:read`, `org:manage` (rename, delete, domains, two-factor rule), `members:read`, `members:manage` (change roles, remove people), `invitations:manage`. Admin has all of them; member has `org:read` and `members:read`. A custom role can include any of them.
- **Admin holds every custom permission** you define, so `has({ permission })` is always true for admins.
- Set a person's role with `PATCH /v1/organizations/{orgId}/members/{userId}` `{ "role": "billing_manager" }` (backend) or `changeOrgRole` (signed-in admins). Invitations and the instance's creator/default role can use custom roles too.
- **No escalation.** Someone can only assign, change or remove roles that their own role covers (every permission of the target role is in theirs). Only admins can grant or touch admin.
- Edits to a role reach people's tokens within a minute. Deleting a role in use is refused. A member whose role no longer exists has no permissions.

## In the session token

With an active organization, the token carries `org_id`, `org_role` and `org_permissions` (an array). Verify on your server and check:

```ts
import { has, protect, verifyToken } from "@daywalker/auth/server";

const claims = await verifyToken(token, config);
if (has(claims, { permission: "org:billing:manage" })) { /* ... */ }
protect(claims, { permission: "org:billing:manage" }); // throws ForbiddenError (status 403)
```

Next.js: `const a = await auth(); a.protect({ permission: "org:billing:manage" });` or `a.has({ role: "billing_manager" })`. `has` needs every key you pass and is false without an active organization. In React, `useAuth().has(...)` and `<Protect permission="…" fallback={…}>` show or hide UI; they read the token in the browser, so **always enforce on the server**.

## Verified domains

An organization admin (permission `org:manage`) can claim email domains: `await auth.addOrgDomain(orgId, "acme.com")`. Free-mail domains (gmail.com and similar) can't be claimed, and only one organization per instance can hold a verified domain.

Prove it one of two ways:

1. **DNS.** Add the TXT record shown (`_daywalker.acme.com` = `daywalker-verify=…`), then `verifyOrgDomainDns`. It can take a while for DNS to spread.
2. **Email.** `sendOrgDomainEmail(orgId, domainId, "postmaster")` sends a 6-digit code to `admin@`, `administrator@`, `postmaster@`, `webmaster@` or `hostmaster@` the domain, then `verifyOrgDomainEmail(orgId, domainId, code)`.

## Joining by domain

Per verified domain, `enrollment` is:

| Value | What happens |
| --- | --- |
| `none` | Nothing (default) |
| `suggest` | People with a **verified** email at the domain see the organization in `listOrgSuggestions()` and can join with `acceptOrgSuggestion(orgId)` |
| `auto_join` | They join on their own when they verify the email or sign in |

Details that keep this safe:

- Only **verified** email addresses count, with an exact domain match (`team.acme.com` is not `acme.com`).
- The role given on joining is the domain's `role` (or the instance default). It can't be `admin` or any role with `org:manage`, `members:manage` or `invitations:manage`.
- The organization's membership limit applies; a full organization isn't joined.
- Removing a domain stops future joins; people who already joined stay.
- Joins are recorded as `org_domain.joined` in the audit log and emit `organizationMembership.created` with `via: "domain"`.

## Errors

`unknown_role` (400), `role_exists` (409), `role_in_use` (409), `role_exceeds_yours` (403), `role_not_allowed` (400), `invalid_domain`, `domain_not_allowed` (400), `domain_taken` (409), `domain_unverified`, `verification_failed` (400).
