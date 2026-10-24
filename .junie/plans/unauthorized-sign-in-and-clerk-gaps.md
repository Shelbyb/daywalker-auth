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

# Testing

- `tsc --noEmit` for the app and `packages/sdk`.
- Request `/unauthorized-sign-in` and `/h/<pk>/unauthorized-sign-in` and check for a 200, strict headers, and branding applied.
- Request an unknown `reason` and check that the generic message is shown.

# Delivery Steps

### * Step 1: Add the Unauthorized sign in page and routing
The `/unauthorized-sign-in` page exists, is branded and reachable on the default and hosted address.

- Create `src/app/(auth)/unauthorized-sign-in/page.tsx` with a fixed reason-to-message map.
- Add the page to the `STRICT` and `HOSTED` regexes in `src/proxy.ts`.
- Redirect refused sign-in, sign-up and SSO failures to it with a reason code.

###   Step 2: Expose the page in the dashboard, SDK and docs
The page is discoverable from the Account Portal tab and the SDK, and documented.

- Add a row to the Overview tab in `hosted/page.tsx`.
- Add the page to the SDK `hostedUrl` page type and `AccountPortalLink`.
- Update `content/docs/guides/account-portal.md`.
- Run `tsc --noEmit` for the app and SDK.

###   Step 3: Write the Clerk gap roadmap
A prioritized list of the missing Clerk features is saved in the repo.

- Check each candidate gap against the code.
- Record confirmed gaps with a short scope note and a priority in `NEXT_STEPS.md`.