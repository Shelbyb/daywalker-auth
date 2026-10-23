"use client";

import { createContext, useContext, useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import { createAuthClient, type AuthClient, type AuthState, type OAuthProvider, type User } from "../core/client";

const Ctx = createContext<AuthClient | null>(null);

/**
 * Wrap your app once (e.g. in app/layout.tsx). Reads config from props or from
 * NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY / NEXT_PUBLIC_DAYWALKER_AUTH_URL.
 */
export function AuthProvider(props: { children: ReactNode; publishableKey?: string; frontendApi?: string; /** Set false to skip the app-domain session cookie (the hosted pages do). */ syncCookie?: boolean }) {
  const [client] = useState(() =>
    createAuthClient({
      publishableKey: props.publishableKey ?? process.env.NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY!,
      frontendApi: props.frontendApi ?? process.env.NEXT_PUBLIC_DAYWALKER_AUTH_URL!,
      ...(props.syncCookie === false ? { syncCookie: false } : {}),
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
    sendSignInCode: c.sendSignInCode,
    checkSSO: c.checkSSO,
    signInWithSSO: c.signInWithSSO,
    signInWithEmailCode: c.signInWithEmailCode,
    signInWithMagicLink: c.signInWithMagicLink,
    listOrganizations: c.listOrganizations,
    createOrganization: c.createOrganization,
    setActiveOrganization: c.setActiveOrganization,
    signUp: c.signUp,
    signOut: c.signOut,
    sendVerificationCode: c.sendVerificationCode,
    verifyEmail: c.verifyEmail,
    requestPasswordReset: c.requestPasswordReset,
    resetPassword: c.resetPassword,
    signInWithOAuth: c.signInWithOAuth,
    completeSecondFactor: c.completeSecondFactor,
    getSecondFactorOptions: c.getSecondFactorOptions,
    sendSecondFactorSms: c.sendSecondFactorSms,
    startSmsSetup: c.startSmsSetup,
    confirmSmsSetup: c.confirmSmsSetup,
    sendSmsCode: c.sendSmsCode,
    removeSmsPhone: c.removeSmsPhone,
    addSecurityKey: c.addSecurityKey,
    listSecurityKeys: c.listSecurityKeys,
    renameSecurityKey: c.renameSecurityKey,
    removeSecurityKey: c.removeSecurityKey,
    completeSecondFactorWithSecurityKey: c.completeSecondFactorWithSecurityKey,
    startTotpSetup: c.startTotpSetup,
    confirmTotpSetup: c.confirmTotpSetup,
    disableTwoFactor: c.disableTwoFactor,
    regenerateBackupCodes: c.regenerateBackupCodes,
    updateProfile: c.updateProfile,
    changePassword: c.changePassword,
    getSecurity: c.getSecurity,
    listSessions: c.listSessions,
    revokeSession: c.revokeSession,
    revokeOtherSessions: c.revokeOtherSessions,
    passkeysSupported: c.passkeysSupported,
    registerPasskey: c.registerPasskey,
    signInWithPasskey: c.signInWithPasskey,
    listPasskeys: c.listPasskeys,
    renamePasskey: c.renamePasskey,
    deletePasskey: c.deletePasskey,
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

const PROVIDER_LABEL: Record<OAuthProvider, string> = {
  google: "Google", github: "GitHub", microsoft: "Microsoft", apple: "Apple", discord: "Discord", gitlab: "GitLab", oidc: "single sign-on",
};

/** "Continue with Google" (or any enabled provider) button. Unstyled; pass className and children to customise. */
export function OAuthButton({ provider, redirectUrl, className, children }: ButtonProps & { provider: OAuthProvider; redirectUrl?: string }) {
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

export { AuthError, type User, type SignInResult, type SessionInfo, type PasskeyInfo, type SecurityKeyInfo, type OAuthProvider, type OrgInfo } from "../core/client";
export { SignIn, SignUp, UserButton, OrganizationSwitcher, type Appearance, type EnvironmentInfo } from "./components";
