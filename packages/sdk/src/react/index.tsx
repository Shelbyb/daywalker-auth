"use client";

import { createContext, useContext, useEffect, useState, useSyncExternalStore, type ReactNode } from "react";
import { ReverificationHost } from "./components";
import { createAuthClient, type AuthClient, type AuthState, type OAuthProvider, type User } from "../core/client";

const Ctx = createContext<AuthClient | null>(null);

/**
 * Clerk-style routing. Set `signInUrl` / `signUpUrl` to your own pages (that render `<SignIn />` / `<SignUp />`)
 * and every button, link and redirect goes there; leave them unset to use the hosted pages.
 * Env: NEXT_PUBLIC_DAYWALKER_SIGN_IN_URL, _SIGN_UP_URL, _SIGN_IN_FALLBACK_REDIRECT_URL, _SIGN_UP_FALLBACK_REDIRECT_URL.
 */
export type AuthUrls = { signInUrl?: string; signUpUrl?: string; signInFallbackRedirectUrl?: string; signUpFallbackRedirectUrl?: string };
const UrlsCtx = createContext<AuthUrls>({});
export const useAuthUrls = () => useContext(UrlsCtx);

/** Where a page lives: your own route when configured, else the hosted page. `redirect_url` is appended either way. */
function usePageUrl() {
  const c = useAuthClient();
  const u = useAuthUrls();
  return (page: "sign-in" | "sign-up" | "forgot-password" | "account" | "unauthorized-sign-in" | "organization" | "create-organization", redirectUrl?: string, opts?: { organizationId?: string }) => {
    const own = page === "sign-in" ? u.signInUrl : page === "sign-up" ? u.signUpUrl : undefined;
    if (!own) return c.hostedUrl(page, redirectUrl, opts);
    if (!redirectUrl || typeof window === "undefined") return own;
    const url = new URL(own, window.location.href);
    url.searchParams.set("redirect_url", redirectUrl);
    return url.origin === window.location.origin ? url.pathname + url.search : url.href;
  };
}

/**
 * Wrap your app once (e.g. in app/layout.tsx). Reads config from props or from
 * NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY / NEXT_PUBLIC_DAYWALKER_AUTH_URL.
 */
export function AuthProvider(props: AuthUrls & { children: ReactNode; publishableKey?: string; frontendApi?: string; /** Verified custom domain for hosted pages. */ hostedDomain?: string; /** Set false to skip the app-domain session cookie (the hosted pages do). */ syncCookie?: boolean; /** Set false to skip the built-in step-up prompt (then register your own with `setReverificationHandler`). */ reverificationPrompt?: boolean }) {
  const [client] = useState(() =>
    createAuthClient({
      publishableKey: props.publishableKey ?? process.env.NEXT_PUBLIC_DAYWALKER_PUBLISHABLE_KEY!,
      frontendApi: props.frontendApi ?? process.env.NEXT_PUBLIC_DAYWALKER_AUTH_URL!,
      ...((props.hostedDomain ?? process.env.NEXT_PUBLIC_DAYWALKER_HOSTED_DOMAIN) ? { hostedDomain: (props.hostedDomain ?? process.env.NEXT_PUBLIC_DAYWALKER_HOSTED_DOMAIN)! } : {}),
      ...(props.syncCookie === false ? { syncCookie: false } : {}),
    }),
  );
  useEffect(() => {
    void client.load();
  }, [client]);
  const [urls] = useState<AuthUrls>(() => ({
    signInUrl: props.signInUrl ?? process.env.NEXT_PUBLIC_DAYWALKER_SIGN_IN_URL,
    signUpUrl: props.signUpUrl ?? process.env.NEXT_PUBLIC_DAYWALKER_SIGN_UP_URL,
    signInFallbackRedirectUrl: props.signInFallbackRedirectUrl ?? process.env.NEXT_PUBLIC_DAYWALKER_SIGN_IN_FALLBACK_REDIRECT_URL,
    signUpFallbackRedirectUrl: props.signUpFallbackRedirectUrl ?? process.env.NEXT_PUBLIC_DAYWALKER_SIGN_UP_FALLBACK_REDIRECT_URL,
  }));
  return <Ctx.Provider value={client}><UrlsCtx.Provider value={urls}>{props.children}{props.reverificationPrompt === false ? null : <ReverificationHost />}</UrlsCtx.Provider></Ctx.Provider>;
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

type HasCheck = { permission?: string; role?: string };
function claimsHas(claims: Record<string, unknown> | null, check: HasCheck) {
  if (!claims || typeof claims.org_id !== "string" || (check.permission === undefined && check.role === undefined)) return false;
  if (check.role !== undefined && claims.org_role !== check.role) return false;
  if (check.permission !== undefined && !(Array.isArray(claims.org_permissions) && claims.org_permissions.includes(check.permission))) return false;
  return true;
}

export function useAuth() {
  const c = useAuthClient();
  const s = useAuthState();
  const sessionClaims = useSessionClaims(c.getToken, s.sessionId);
  return {
    /**
     * Does the active organization role have this permission/role? For showing or hiding UI only:
     * enforce on your server with `has()` / `protect()` from `@daywalker/auth/server`.
     */
    has: (check: HasCheck) => claimsHas(sessionClaims, check),
    isLoaded: s.isLoaded,
    isSignedIn: s.isLoaded ? !!s.sessionId : undefined,
    userId: s.user?.id ?? null,
    sessionId: s.sessionId,
    /** Signed in, but the app requires two-step verification first: send them to the account page. */
    twoFactorSetupRequired: s.twoFactorSetupRequired === true,
    getToken: c.getToken,
    /** Decoded claims of the current token, including custom claims set in the dashboard. Null until signed in. */
    sessionClaims,
    /** `fetch` with your session token. Answers 403 `reverification_required` by showing the step-up prompt and retrying once. */
    authFetch: c.authFetch,
    /** Show the step-up prompt yourself; resolves true once the person proved themselves. */
    requestReverification: c.requestReverification,
    getReverificationOptions: c.getReverificationOptions,
    reverifyWithPassword: c.reverifyWithPassword,
    reverifyWithCode: c.reverifyWithCode,
    reverifyWithPasskey: c.reverifyWithPasskey,
    reverifyWithSecurityKey: c.reverifyWithSecurityKey,
    sendReverificationEmailCode: c.sendReverificationEmailCode,
    reverifyWithEmailCode: c.reverifyWithEmailCode,
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
    deleteAccount: c.deleteAccount,
    exportData: c.exportData,
    getReauthRequirements: c.getReauthRequirements,
    sendReauthCode: c.sendReauthCode,
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
/** Renders children only when the active organization role has the permission (UI convenience, not security). */
export function Protect({ permission, role, children, fallback = null }: HasCheck & { children: ReactNode; fallback?: ReactNode }) {
  const { has } = useAuth();
  return <>{has({ permission, role }) ? children : fallback}</>;
}

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
  const pageUrl = usePageUrl();
  return (
    <button type="button" className={className} onClick={() => window.location.assign(pageUrl(mode, redirectUrl ?? window.location.href))}>
      {children}
    </button>
  );
}

/** Sends the user to the hosted sign-up page. */
export function SignUpButton(props: ButtonProps & { redirectUrl?: string }) {
  return <SignInButton {...props} mode="sign-up">{props.children ?? "Sign up"}</SignInButton>;
}

/** Opens the hosted account page (password, two-factor, passkeys, devices), with a link back to your app. */
export function AccountButton({ children = "Manage account", className, redirectUrl }: ButtonProps & { redirectUrl?: string }) {
  const c = useAuthClient();
  return (
    <button type="button" className={className} onClick={() => window.location.assign(c.hostedUrl("account", redirectUrl ?? window.location.href))}>
      {children}
    </button>
  );
}

/** Immediately sends signed-out visitors to the hosted sign-in page; they return to `redirectUrl` (default: this page). */
export function RedirectToSignIn({ redirectUrl, mode = "sign-in" }: { redirectUrl?: string; mode?: "sign-in" | "sign-up" }) {
  const pageUrl = usePageUrl();
  const s = useAuthState();
  useEffect(() => {
    if (s.isLoaded && !s.sessionId) window.location.replace(pageUrl(mode, redirectUrl ?? window.location.href));
  }, [s.isLoaded, s.sessionId, mode, redirectUrl]); // eslint-disable-line react-hooks/exhaustive-deps
  return null;
}

/**
 * A plain `<a>` link to a hosted page, for when you'd rather not embed the SDK component.
 * The user comes back to the current URL (or `redirectUrl`) when done.
 */
export function HostedLink({ page, children, className, redirectUrl, organizationId }: ButtonProps & { page: "sign-in" | "sign-up" | "forgot-password" | "account" | "unauthorized-sign-in" | "organization" | "create-organization"; redirectUrl?: string | false; organizationId?: string }) {
  const c = useAuthClient();
  const pageUrl = usePageUrl();
  const [href, setHref] = useState(() => c.hostedUrl(page, redirectUrl || undefined));
  useEffect(() => setHref(pageUrl(page, redirectUrl === false ? undefined : redirectUrl ?? window.location.href, { organizationId })), [page, redirectUrl, organizationId]); // eslint-disable-line react-hooks/exhaustive-deps
  const label = { "sign-in": "Sign in", "sign-up": "Sign up", "forgot-password": "Forgot password?", account: "Manage account", "unauthorized-sign-in": "Unauthorized sign in", organization: "Manage organization", "create-organization": "Create organization" }[page];
  return <a href={href} className={className}>{children ?? label}</a>;
}

/** `redirectUrl={false}` leaves it off, so the Account Portal's fallback redirects (dashboard > Account Portal > Redirects) apply. */
type HostedProps = ButtonProps & { redirectUrl?: string | false };
/** Link to the hosted sign-in page (hosted counterpart of `<SignIn />`). */
export const HostedSignIn = (p: HostedProps) => <HostedLink {...p} page="sign-in" />;
/** Link to the hosted sign-up page (hosted counterpart of `<SignUp />`). */
export const HostedSignUp = (p: HostedProps) => <HostedLink {...p} page="sign-up" />;
/** Link to the hosted forgot-password page. */
export const HostedForgotPassword = (p: HostedProps) => <HostedLink {...p} page="forgot-password" />;
/** Link to the hosted account page (hosted counterpart of `<UserProfile />`). */
export const HostedUserProfile = (p: HostedProps) => <HostedLink {...p} page="account" />;
export const HostedOrganizationProfile = (p: HostedProps & { organizationId?: string }) => <HostedLink {...p} page="organization" />;
export const HostedCreateOrganization = (p: HostedProps) => <HostedLink {...p} page="create-organization" />;

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
        const { redirecting } = await c.signOut({ redirectUrl: afterSignOutUrl });
        if (afterSignOutUrl && !redirecting) window.location.assign(afterSignOutUrl);
      }}
    >
      {children}
    </button>
  );
}

export { AuthError, type User, type SignInResult, type SessionInfo, type PasskeyInfo, type SecurityKeyInfo, type OAuthProvider, type OrgInfo, type Reauth, type ReauthRequirements, type OrgRoleInfo, type OrgDomainInfo, type OrgSuggestion, type OrganizationSettings } from "../core/client";
export { SignIn, SignUp, UserButton, UserProfile, OrganizationSwitcher, CreateOrganization, OrganizationProfile, Captcha, ReverificationPrompt, type Appearance, type EnvironmentInfo } from "./components";

/** Account Portal names for the hosted links (same components). */
export const AccountPortalLink = HostedLink;
export { HostedOrganizationProfile as AccountPortalOrganization, HostedCreateOrganization as AccountPortalCreateOrganization };
export { HostedSignIn as AccountPortalSignIn, HostedSignUp as AccountPortalSignUp, HostedUserProfile as AccountPortalProfile };

function useSessionClaims(getToken: () => Promise<string | null>, sessionId: string | null) {
  const [claims, setClaims] = useState<Record<string, unknown> | null>(null);
  useEffect(() => {
    if (!sessionId) { setClaims(null); return; }
    let live = true;
    getToken().then((t) => {
      if (!live || !t) return;
      try {
        const b = t.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
        setClaims(JSON.parse(decodeURIComponent(escape(atob(b)))));
      } catch { setClaims(null); }
    }).catch(() => undefined);
    return () => { live = false; };
  }, [getToken, sessionId]);
  return claims;
}
