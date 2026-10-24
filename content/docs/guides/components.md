---
title: Drop-in components
description: Put sign-in, sign-up, an account menu and an organization switcher on your own pages.
---

# Drop-in components

The [hosted pages](/docs/quickstart) are the quickest way to add auth. When you'd rather keep people on your own site, render the same flows with four React components:

| Component | What it does |
|---|---|
| `<SignIn />` | Password, passkey, social buttons, email codes, and the two-factor step when needed |
| `<SignUp />` | Name, email and password, your terms checkbox if required, social buttons, then email verification |
| `<UserButton />` | Avatar menu with the user's name, **Manage account** and **Sign out** |
| `<OrganizationSwitcher />` | Switch between the personal account and organizations, or create a new organization |

They read your instance's settings, so enabling GitHub or email codes in the dashboard makes the matching option appear without a code change.

## Add them

```tsx
// app/layout.tsx
import "@daywalker/auth/styles.css"; // optional default look
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

```tsx
// app/sign-in/page.tsx
"use client";
import { SignIn } from "@daywalker/auth/react";

export default function Page() {
  return <SignIn redirectUrl="/dashboard" signUpUrl="/sign-up" />;
}
```

```tsx
// app/sign-up/page.tsx
"use client";
import { SignUp } from "@daywalker/auth/react";

export default function Page() {
  return <SignUp redirectUrl="/dashboard" signInUrl="/sign-in" />;
}
```

```tsx
// In your header
"use client";
import { OrganizationSwitcher, SignedIn, UserButton } from "@daywalker/auth/react";

export function Header() {
  return (
    <SignedIn>
      <OrganizationSwitcher />
      <UserButton afterSignOutUrl="/sign-in" />
    </SignedIn>
  );
}
```

Your app's origin must be in the instance's **allowed origins** (dashboard → Settings).

## Props

| Component | Props |
|---|---|
| `<SignIn>` | `redirectUrl?`, `onSignedIn?(user)`, `signUpUrl?`, `appearance?`, `initialEnvironment?`, `initialError?`, `signedIn?` |
| `<SignUp>` | `redirectUrl?`, `onSignedIn?(user)`, `signInUrl?`, `appearance?`, `initialEnvironment?`, `initialError?`, `signedIn?` |

When the app has the [human check](/docs/guides/sign-up-protection) on, `<SignUp />`, `<SignIn />` (password and email-code forms) and the hosted password reset show the Turnstile widget. When the app [requires two-factor](/docs/guides/two-factor#requiring-2fa), they send people without it to the account page.

`initialEnvironment` is the settings you already fetched on the server (skips the request and the loading flash), `initialError` is an error code from a redirect back (shown as a fixed message, never raw text from the URL), and `signedIn` shows the signed-in state straight away. The hosted sign-in and sign-up pages at `users.daywalker.dev` are these same components, so what you build matches them.
| `<UserButton>` | `afterSignOutUrl?`, `className?`, `appearance?` |
| `<OrganizationSwitcher>` | `hidePersonal?`, `onChange?(org)`, `appearance?` |

`onSignedIn` replaces the redirect, for example to close a modal. Social sign-in always does a full-page redirect and comes back to `redirectUrl` (or the current page).

## Styling

There are three ways to style the components; mix them as you like:

1. **The default stylesheet.** Import `@daywalker/auth/styles.css`, then adjust it with CSS variables:

   ```css
   .dw-root, .dw-user-button, .dw-org-switcher {
     --dw-accent: #4f46e5;
     --dw-radius: 6px;
     --dw-font: "Inter", sans-serif;
   }
   ```

   Add the class `dw-dark` to `<html>` (or any parent) for the dark theme.

2. **Your own CSS.** Every element has a stable class: `dw-root`, `dw-title`, `dw-input`, `dw-button-primary`, `dw-provider-github`, `dw-menu-item` and so on. Skip the stylesheet and style them yourself.

3. **Your own classes**, for Tailwind or a design system:

   ```tsx
   <SignIn appearance={{ classNames: { button: "btn btn-primary", input: "input input-bordered" } }} />
   ```

   Parts: `root`, `header`, `title`, `subtitle`, `form`, `field`, `label`, `input`, `button`, `buttonSecondary`, `providers`, `divider`, `error`, `info`, `footer`, `link`, `checkbox`, `userButton`, `avatar`, `menu`, `menuItem`, `orgSwitcher`.

## Security notes

- **Works under a strict Content Security Policy.** The components use no inline styles and never inject HTML.
- **The server makes the decisions.** Origins, redirects, rate limits, breached passwords and two-factor are all enforced by Daywalker, not by the component, so a modified component can't skip them.
- **The organization switcher only displays.** It reads the active organization from the session token to show it; your server must still check `orgId` and `orgRole` from a verified token before acting on them.
