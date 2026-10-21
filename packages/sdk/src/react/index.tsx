"use client";

import { createContext, useContext, useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import { createAuthClient, type AuthClient, type AuthState, type User } from "../core/client";

const Ctx = createContext<AuthClient | null>(null);

/**
 * Wrap your app once (e.g. in app/layout.tsx). Reads config from props or from
 * NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY / NEXT_PUBLIC_DAYWALKER_AUTH_URL.
 */
export function AuthProvider(props: { children: ReactNode; publishableKey?: string; frontendApi?: string }) {
  const [client] = useState(() =>
    createAuthClient({
      publishableKey: props.publishableKey ?? process.env.NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY!,
      frontendApi: props.frontendApi ?? process.env.NEXT_PUBLIC_DAYWALKER_AUTH_URL!,
    }),
  );
  useEffect(() => {
    void client.load();
  }, [client]);
  return <Ctx.Provider value={client}>{props.children}</Ctx.Provider>;
}

export function useAuthClient() {
  const c = useContext(Ctx);
  if (!c) throw new Error("Wrap your app in <AuthProvider>");
  return c;
}

const SERVER_STATE: AuthState = { isLoaded: false, user: null, sessionId: null };

function useAuthState() {
  const c = useAuthClient();
  return useSyncExternalStore(c.subscribe, () => c.state, () => SERVER_STATE);
}

export function useAuth() {
  const c = useAuthClient();
  const s = useAuthState();
  return {
    isLoaded: s.isLoaded,
    isSignedIn: s.isLoaded ? !!s.sessionId : undefined,
    userId: s.user?.id ?? null,
    sessionId: s.sessionId,
    getToken: c.getToken,
    authFetch: c.authFetch,
    signIn: c.signIn,
    signUp: c.signUp,
    signOut: c.signOut,
    sendVerificationCode: c.sendVerificationCode,
    verifyEmail: c.verifyEmail,
    requestPasswordReset: c.requestPasswordReset,
    resetPassword: c.resetPassword,
    signInWithOAuth: c.signInWithOAuth,
  };
}

export function useUser(): { isLoaded: boolean; user: User | null } {
  const s = useAuthState();
  return { isLoaded: s.isLoaded, user: s.user };
}

/** Renders children only once loaded and signed in. */
export function SignedIn({ children }: { children: ReactNode }) {
  const s = useAuthState();
  return s.isLoaded && s.sessionId ? <>{children}</> : null;
}

/** Renders children only once loaded and signed out. */
export function SignedOut({ children }: { children: ReactNode }) {
  const s = useAuthState();
  return s.isLoaded && !s.sessionId ? <>{children}</> : null;
}

type ButtonProps = { children?: ReactNode; className?: string };

/** Sends the user to the hosted page and back to the current URL (or `redirectUrl`). */
export function SignInButton({ children = "Sign in", className, mode = "sign-in", redirectUrl }: ButtonProps & { mode?: "sign-in" | "sign-up"; redirectUrl?: string }) {
  const c = useAuthClient();
  return (
    <button type="button" className={className} onClick={() => window.location.assign(c.hostedUrl(mode, redirectUrl ?? window.location.href))}>
      {children}
    </button>
  );
}

const PROVIDER_LABEL = { google: "Google", github: "GitHub" } as const;

/** "Continue with Google/GitHub" button. Unstyled; pass className and children to customise. */
export function OAuthButton({ provider, redirectUrl, className, children }: ButtonProps & { provider: "google" | "github"; redirectUrl?: string }) {
  const c = useAuthClient();
  return (
    <button type="button" className={className} onClick={() => c.signInWithOAuth(provider, redirectUrl)}>
      {children ?? `Continue with ${PROVIDER_LABEL[provider]}`}
    </button>
  );
}

export function SignOutButton({ children = "Sign out", className, afterSignOutUrl }: ButtonProps & { afterSignOutUrl?: string }) {
  const c = useAuthClient();
  return (
    <button
      type="button"
      className={className}
      onClick={async () => {
        await c.signOut();
        if (afterSignOutUrl) window.location.assign(afterSignOutUrl);
      }}
    >
      {children}
    </button>
  );
}

/** Avatar with a small menu. Unstyled except for minimal inline layout; pass className to theme. */
export function UserButton({ className, afterSignOutUrl }: { className?: string; afterSignOutUrl?: string }) {
  const { user } = useUser();
  const c = useAuthClient();
  const [open, setOpen] = useState(false);
  if (!user) return null;
  const email = user.emailAddresses.find((e) => e.primary)?.email ?? user.emailAddresses[0]?.email ?? "";
  const name = [user.firstName, user.lastName].filter(Boolean).join(" ") || email;
  const initials = (user.firstName?.[0] ?? email[0] ?? "?").toUpperCase() + (user.lastName?.[0] ?? "").toUpperCase();
  return (
    <div className={className} style={{ position: "relative", display: "inline-block" }}>
      <button type="button" aria-haspopup="menu" aria-expanded={open} aria-label={`Account: ${name}`} onClick={() => setOpen((o) => !o)}
        style={{ width: 36, height: 36, borderRadius: 999, border: "none", background: "#2a2536", color: "#fff", fontSize: 13, fontWeight: 600, cursor: "pointer" }}>
        {initials}
      </button>
      {open && (
        <div role="menu" style={{ position: "absolute", right: 0, top: 44, minWidth: 220, background: "#fff", border: "1px solid #e7e5e4", borderRadius: 12, padding: 12, boxShadow: "0 10px 30px rgba(0,0,0,.12)", zIndex: 50 }}>
          <div style={{ fontWeight: 600, fontSize: 14 }}>{name}</div>
          {name !== email && <div style={{ fontSize: 12, color: "#78716c" }}>{email}</div>}
          <button role="menuitem" type="button" onClick={async () => { await c.signOut(); setOpen(false); if (afterSignOutUrl) window.location.assign(afterSignOutUrl); }}
            style={{ marginTop: 10, width: "100%", textAlign: "left", background: "none", border: "none", padding: "6px 0", fontSize: 14, cursor: "pointer" }}>
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}

export { AuthError, type User } from "../core/client";
