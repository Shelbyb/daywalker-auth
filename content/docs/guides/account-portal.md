---
title: Account Portal
description: Fully hosted sign-in, sign-up, password reset and account pages, set up from the dashboard.
---

# Account Portal

The Account Portal is a set of pages we host for your instance: **sign in**, **sign up**, **forgot password** and the **user profile** (account page). They support everything the SDK components do: email and password, email codes, social sign-in, passkeys, two-factor and password reset. Use the portal instead of the components, or alongside them.

## Set it up in the dashboard

1. Open your instance and go to **Configure → Customization → Account Portal**.
2. **Overview** lists the portal's links. Copy one with the copy button, or open it with ↗. **View** in the top right opens the sign-in page.
3. Under **Configure → User & authentication → Sign-in & security**, add your app's origin (for example `https://app.example.com`) to **Allowed origins**. The portal only sends people back to allowed origins.
4. Optional: set **Redirects** and **Customization** (below).

By default the links look like `https://users.daywalker.dev/h/<publishable key>/sign-in`. Once a custom domain is verified, they become `https://accounts.example.com/sign-in`, and the default links redirect there.

## Redirects

Add `?redirect_url=https://app.example.com/somewhere` to any portal link to send people back to that page afterwards. When a link has no `redirect_url`, the portal uses the fallbacks from the **Redirects** tab:

| Setting | Used when |
|---|---|
| After sign-up fallback | Someone finishes signing up |
| After sign-in fallback | Someone finishes signing in |
| After logo click | Someone clicks your logo on the portal |

Each URL must be on one of your allowed origins, or saving fails.

## Unauthorized sign in

When your instance refuses someone, the portal sends them to `/unauthorized-sign-in?reason=<code>` instead of showing a raw error. The page uses your branding and links back to sign in (and to your "After logo click" URL when set). Reasons are coarse so they never reveal whether an account exists:

| `reason` | Shown when |
|---|---|
| `sign_up_restricted` | Sign-up is blocked by your email domain rules |
| `account_locked` | The account is suspended |
| `origin_not_allowed` | The request came from an origin not in your allowed origins |
| `sso_failed` | An SSO sign-in could not be completed |

Any other value shows a generic message. With the SDK, pass `unauthorizedUrl` to `<SignIn>` / `<SignUp>` to send refusals to your own page (with `?reason=` added), or link to the portal page with `<AccountPortalLink page="unauthorized-sign-in" />`.

## Customization

The **Customization** tab has:

- **Appearance:** logo (https URL), heading, button color and background color (hex, like `#ff6a3d`).
- **Custom domain:** serve the portal from your own hostname.

### Custom domain

1. Enter a hostname such as `accounts.example.com` and click **Add domain**.
2. Where you manage DNS, add the one CNAME record shown, pointing your hostname at our address. Keep it DNS-only (not proxied).
3. Wait. We check automatically each time you open the page, or click **Check now**. Once it's verified we issue the certificate and the portal serves from your hostname.

Use a subdomain: most DNS providers don't allow a CNAME on the bare domain.

## Link to it from your app

The React SDK has links for each portal page. See [React SDK](/docs/sdk/react#embedded-component-or-hosted-page).

```tsx
import { AccountPortalSignIn, AccountPortalProfile } from "@daywalker/auth/react";

<AccountPortalSignIn />                  {/* returns to the current page */}
<AccountPortalSignIn redirectUrl={false} /> {/* uses the "After sign-in fallback" */}
<AccountPortalProfile>Manage account</AccountPortalProfile>
```

If you use a custom domain, set `hostedDomain` on `<AuthProvider>` (or `NEXT_PUBLIC_DAYWALKER_HOSTED_DOMAIN`) so links go straight there.
