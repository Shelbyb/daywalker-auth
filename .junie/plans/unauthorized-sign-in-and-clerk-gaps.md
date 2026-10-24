---
sessionId: session-261023-202900-nupq
---

# Requirements

### Overview & Goals
Add a Clerk-style **Unauthorized sign in** page to the Account Portal, then list and plan the other Clerk features this service lacks.

### In Scope
- New `/unauthorized-sign-in` page, in the `(auth)` group so it gets the same branding and strict headers as the other portal pages.
- A reachable path to it: the sign-in and sign-up flows send a user there when the instance refuses them. Reasons: sign-up is blocked by the instance's restrictions, the account is banned or locked, the origin is not allowed, or an SSO login fails.
- Account Portal page link in the dashboard Overview tab, docs entry in `guides/account-portal.md`, and a `?reason=` code that maps to fixed, non-leaking messages.
- A gap analysis (below) as a roadmap. It is not built in this change.

### Out of Scope
Building the gap-analysis items. They are only planned.

### Clerk gaps to plan (to be confirmed against current code before work starts)
1. Allowlist/blocklist of email domains and identifiers per instance.
2. Waitlist / restricted sign-up mode.
3. Ban/lock a user from the dashboard, with a message on the unauthorized page.
4. Session token customization (custom claims / JWT templates).
5. Bot protection configuration per instance (Turnstile exists already).
6. Organization roles and permissions customization, plus domain-based auto-join.
7. Account Portal pages: organization switcher, create organization, and the unauthorized page.
8. SDK `<OrganizationSwitcher>`, `<CreateOrganization>`, `<OrganizationProfile>` components.
9. Development vs production instance cloning.
10. Satellite domains / multi-domain support.

# Technical Design

### Current Implementation
- Portal pages live in `src/app/(auth)/{sign-in,sign-up,forgot-password,second-factor,magic-link,accept-invite}`. `src/proxy.ts` has a `STRICT` regex of the strict-header pages and a `HOSTED` regex that maps `/h/<pk>/<page>` to them.
- Branding and redirect fallbacks are applied through `src/app/components/brand-style.tsx` and `instance.settings.redirects`.

### Proposed Changes
- Add `src/app/(auth)/unauthorized-sign-in/page.tsx`. It is a server component that resolves the instance the same way `sign-in/page.tsx` does, then shows a heading, a short message chosen from a fixed `reason` map, and links back to sign-in and to the instance's `afterLogoClick` redirect when set. Unknown reasons fall back to a generic message.
- Update `src/proxy.ts`: add `unauthorized-sign-in` to `STRICT` and to the `HOSTED` regex.
- Redirect to it from the sign-in, sign-up and SSO callback failure paths. Pass only a reason code, never the raw error text.
- Add the link to `hosted/page.tsx` Overview, add `AccountPortalLink` page `unauthorized-sign-in` in the SDK `hostedUrl` page union, and document it in `content/docs/guides/account-portal.md`.
- Write the gap analysis to `NEXT_STEPS.md` as a prioritized list.

### Risks
Messages must not reveal whether an account exists. Keep the reason codes coarse.

### Organization settings (follow-up request, Clerk-style)
Current: `organizations` / `memberships` tables in `src/lib/db/schema.ts` (roles `admin`/`member`, per-org `requireTwoFactor`), client routes under `src/app/v1/client/organizations/**`, backend routes under `src/app/v1/organizations/**`.

Add an instance-level `settings.organizations` object (in the `instances.settings` jsonb, no migration needed):
```ts
organizations?: {
  enabled?: boolean;            // default true (current behaviour)
  membershipLimit?: number | null; // max members per org, null = unlimited
  allowUserCreation?: boolean;  // users may create orgs from the client API
  creationLimit?: number | null;   // max orgs a user may create
  creatorRole?: "admin" | "member"; // default admin
  defaultRole?: "admin" | "member"; // role for invited/joined members
  allowAdminDelete?: boolean;   // org admins may delete their org
  allowPersonalAccounts?: boolean; // if false, users must have an active org
}
```
- Enforce in the client routes: create (enabled, allowUserCreation, creationLimit, creatorRole), invitations/accept + SSO join (membershipLimit, defaultRole), DELETE org (allowAdminDelete), `session/active_org` (allowPersonalAccounts forbids clearing). Errors use existing `forbidden`/`limit_reached` codes. Backend API is exempt except membershipLimit.
- Expose settings in the frontend environment response so the SDK can read them.
- Dashboard: new **Configure → User & authentication → Organizations** page with `Toggle`s and number fields, a server action validating input and writing the instance audit log.
- SDK: add the settings to the environment type in `packages/sdk/src/core/client.ts`; hide create/delete/leave-personal UI accordingly; surface the new errors.
- Docs: new `content/docs/guides/organizations.md` section on these settings (dashboard steps + SDK behaviour), nav + help-sidebar entry; update `api/*` org endpoint error docs.

### Session settings (follow-up request, Clerk "Sessions" page)
Current: `instances.settings` already has `sessionLifetimeDays` and `tokenTtlSeconds`; sessions logic is in `src/lib/auth/sessions.ts`.

Extend `instances.settings` (jsonb, no migration):
```ts
sessions?: {
  maxLifetimeEnabled?: boolean;      // uses existing sessionLifetimeDays
  inactivityTimeoutMinutes?: number | null; // end session after N idle minutes
  multiSession?: boolean;            // allow several signed-in accounts per browser
  customClaims?: Record<string, string>; // session token claim templates, e.g. {"email": "{{user.email}}"}
}
```
- Enforce in `sessions.ts`: reject/expire on inactivity (compare `lastActiveAt`), single-session mode revokes other sessions in the same client on sign-in.
- Token issuance merges validated custom claims (reserved claims like `sub`, `iss`, `exp`, `sid` refused; size limit).
- Dashboard: **Configure → User & authentication → Sessions** page with lifetime, inactivity, multi-session toggle, token lifetime and a JSON claims editor with preview; audit-logged action.
- SDK: expose settings in the environment type; decoded custom claims available on `useAuth().sessionClaims`; multi-session account switching helper when enabled.
- Docs: `content/docs/guides/sessions.md` (dashboard setup, claims template syntax, SDK usage), nav and help-sidebar entry.

# Testing

- `tsc --noEmit` for the app and `packages/sdk`.
- Request `/unauthorized-sign-in` and `/h/<pk>/unauthorized-sign-in` and check for a 200, strict headers, and branding applied.
- Request an unknown `reason` and check that the generic message is shown.

# Delivery Steps

### ✓ Step 1: Add the Unauthorized sign in page and routing
The `/unauthorized-sign-in` page exists, is branded and reachable on the default and hosted address.

- Create `src/app/(auth)/unauthorized-sign-in/page.tsx` with a fixed reason-to-message map.
- Add the page to the `STRICT` and `HOSTED` regexes in `src/proxy.ts`.
- Redirect refused sign-in, sign-up and SSO failures to it with a reason code.

### ✓ Step 2: Expose the page in the dashboard, SDK and docs
The page is discoverable from the Account Portal tab and the SDK, and documented.

- Add a row to the Overview tab in `hosted/page.tsx`.
- Add the page to the SDK `hostedUrl` page type and `AccountPortalLink`.
- Update `content/docs/guides/account-portal.md`.
- Run `tsc --noEmit` for the app and SDK.

### ✓ Step 3: Write the Clerk gap roadmap
A prioritized list of the missing Clerk features is saved in the repo.

- Check each candidate gap against the code.
- Record confirmed gaps with a short scope note and a priority in `NEXT_STEPS.md`.

### * Step 4: Add and enforce instance organization settings
Organization settings are stored per instance, editable in the dashboard, and enforced by the API.

- Add `settings.organizations` type in `schema.ts`.
- Enforce in `src/app/v1/client/organizations/**`, invitations, SSO join and `session/active_org`.
- Add the Organizations Configure page, action and audit entry.
- Extend an e2e script with checks for each limit/toggle; run typecheck.

###   Step 5: SDK support and documentation for organization settings
The SDK reads and respects the settings, and the docs explain them.

- Expose settings in the environment response and SDK types; adapt org components/errors.
- Write the organizations settings docs, nav and help-sidebar entries.
- Typecheck app, SDK and example.

###   Step 6: Add and enforce session settings
Session lifetime, inactivity timeout, multi-session and custom claims are configurable and enforced.

- Add `settings.sessions` type; enforce in `src/lib/auth/sessions.ts` and token issuance.
- Add the Sessions Configure page, action and audit entry.
- Add e2e checks for inactivity expiry, single-session revoke and claim validation.

###   Step 7: SDK support and docs for session settings
The SDK exposes custom claims and multi-session, and docs explain setup.

- Update SDK types, `useAuth` claims and session switching.
- Write `guides/sessions.md`, nav and help-sidebar entries; typecheck app, SDK and example.

###   Step 8: Plans, subscriptions and Stripe billing
Developer accounts have a plan (free by default) and can upgrade through Stripe.

- Add `plans` and `subscriptions` tables with a migration seeding the free plan.
- Add the Platform → Configure → Plans admin page and audit-logged action.
- Add Stripe Checkout, customer portal and the signed webhook; add the dashboard Billing page.

###   Step 9: Feature gating, marketing pricing and plan badges in docs
Paid features are enforced and labelled with the plan they need.

- Add `planAllows` and gate paid settings in dashboard pages and actions, with plan badges.
- Add a pricing section to the marketing page from the active plans.
- Add the `plan:` front-matter badge and inline badges to the docs; typecheck and build.
- Badge style (Clerk): small rounded pill with the plan name (e.g. "Pro") next to the feature title, in dashboard settings and docs headings.
