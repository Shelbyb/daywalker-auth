---
title: "@daywalker/auth/react"
description: Provider, hooks and components for React and Next.js client components.
---

```bash
npm install @daywalker/auth
```

Everything here is a client component or hook. In Next.js, use it from files marked `"use client"` (the `<AuthProvider>` itself can sit in a server layout).

## `<AuthProvider>`

Loads the session and keeps the token fresh. Wrap your whole app once.

```tsx
<AuthProvider publishableKey="pk_test_…" frontendApi="https://users.daywalker.dev">
  {children}
</AuthProvider>
```

| Prop | Type | Default |
|---|---|---|
| `publishableKey` | `string` | `process.env.NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY` |
| `frontendApi` | `string` | `process.env.NEXT_PUBLIC_DAYWALKER_AUTH_URL` |

## `useAuth()`

```ts
const {
  isLoaded,      // false until the first session check finishes
  isSignedIn,    // undefined while loading, then true/false
  userId,        // string | null
  sessionId,     // string | null
  getToken,      // () => Promise<string | null>
  authFetch,     // fetch with Authorization header
  signIn,        // ({ email, password }) => Promise<SignInResult>
                 //   { status: "complete", user } | { status: "needs_second_factor" }
  completeSecondFactor, // (code) => Promise<{ status: "complete", user }>
  signUp,        // ({ email, password, firstName?, lastName? }) => Promise<User>
  signOut,       // () => Promise<void>
  sendVerificationCode, // () => Promise<void>
  verifyEmail,          // (code) => Promise<User>
  requestPasswordReset, // (email) => Promise<void>
  resetPassword,        // ({ email, code, password }) => Promise<void>
  signInWithOAuth,      // (OAuthProvider, redirectUrl?) => void (full-page redirect)
  startTotpSetup,       // () => Promise<{ secret, uri }>
  confirmTotpSetup,     // (code) => Promise<string[]> backup codes
  disableTwoFactor,     // (code) => Promise<void>
  regenerateBackupCodes,// (code) => Promise<string[]>
  updateProfile,        // ({ firstName?, lastName? }) => Promise<User>
  changePassword,       // ({ currentPassword, newPassword }) => Promise<{ otherSessionsSignedOut }>
  getSecurity,          // () => Promise<SecurityInfo>
  listSessions,         // () => Promise<SessionInfo[]>
  revokeSession,        // (sessionId) => Promise<void>
  revokeOtherSessions,  // () => Promise<number>
  passkeysSupported,    // () => boolean
  signInWithPasskey,    // () => Promise<{ status: "complete", user }>
  registerPasskey,      // (name?) => Promise<{ id }>  (needs a sign-in from the last 15 min)
  listPasskeys,         // () => Promise<PasskeyInfo[]>
  renamePasskey,        // (id, name) => Promise<void>
  deletePasskey,        // (id) => Promise<void>
} = useAuth();
```

Actions throw [`AuthError`](/docs/api/errors) when the server rejects them.

## `useUser()`

```ts
const { isLoaded, user } = useUser(); // user: User | null
```

See [Read the current user](/docs/guides/read-user#on-the-client) for the `User` shape.

## `useAuthClient()`

Returns the underlying [browser client](/docs/sdk/client), for example to build hosted-page URLs with `hostedUrl()`.

## Components

| Component | Renders |
|---|---|
| `<SignedIn>` | Its children, only when loaded and signed in |
| `<SignedOut>` | Its children, only when loaded and signed out |
| `<SignInButton mode? redirectUrl? className?>` | A button that opens the hosted sign-in (or `mode="sign-up"`) page and returns to `redirectUrl` (default: current page) |
| `<OAuthButton provider redirectUrl? className?>` | "Continue with Google/GitHub". See [Social sign-in](/docs/guides/social-sign-in). |
| `<SignOutButton afterSignOutUrl? className?>` | A button that signs out, then optionally navigates |
| `<UserButton afterSignOutUrl? className?>` | Initials avatar with name, email, **Manage account** ([account page](/docs/guides/account-page)) and **Sign out** |

All buttons accept `children` to change their label:

```tsx
<SignInButton className="btn">Log in to continue</SignInButton>
```
