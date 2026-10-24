import { ACTIVE_COOKIE, SESSION_COOKIE, instanceIdFromKey, normalizeOrigin, type Config } from "./keys";
import type { RecentAuthCheck } from "./fresh";
import { assertSatelliteConfig, SATELLITE_SIGNED_OUT_COOKIE, SATELLITE_SYNC_PATH } from "./satellite";
import { createDpopProof, deviceKeysSupported, generateDeviceKey, indexedDbKeyStore, type DeviceKey, type DeviceKeyStore } from "./dpop";
import { startRegistration, startAuthentication, browserSupportsWebAuthn, browserSupportsWebAuthnAutofill, WebAuthnAbortService } from "@simplewebauthn/browser";

export type EmailAddress = { id: string; email: string; primary: boolean; verified: boolean };
export type User = {
  id: string;
  firstName: string | null;
  lastName: string | null;
  imageUrl: string | null;
  emailAddresses: EmailAddress[];
  publicMetadata: Record<string, unknown>;
  twoFactorEnabled: boolean;
  lastSignInAt: string | null;
  createdAt: string;
};
export type AuthState = {
  isLoaded: boolean;
  user: User | null;
  sessionId: string | null;
  /** The app requires two-step verification and this person hasn't set it up: no session token until they do (send them to the account page). */
  twoFactorSetupRequired?: boolean;
};

/** `needs_second_factor`: password/provider was right; call `completeSecondFactor(code)` next. */
export type OAuthProvider = "google" | "github" | "microsoft" | "apple" | "discord" | "gitlab" | "oidc";

/** `needs_two_factor_setup`: signed in, but the app requires two-step verification first (see `hostedUrl("account")`). */
export type SignInResult = { status: "complete"; user: User } | { status: "needs_second_factor" } | { status: "needs_two_factor_setup"; user: User };

export type ApiKeyInfo = { id: string; name: string; prefix: string; scopes: string[]; subject: { type: "user" | "org"; id: string }; createdBy: string | null; expiresAt: string | null; lastUsedAt: string | null; revokedAt: string | null; createdAt: string };
export type SessionInfo = { id: string; current: boolean; device: string; ipHint: string | null; lastActiveAt: string; createdAt: string };
export type SecurityInfo = {
  hasPassword: boolean;
  twoFactorEnabled: boolean;
  /** An authenticator app is set up. */
  totpEnabled: boolean;
  /** The two-factor phone, masked ("+1 ••• ••• 0100"), or null. */
  smsPhone: string | null;
  /** This app allows SMS two-factor. */
  smsAvailable: boolean;
  /** Security keys (YubiKey and similar) used as a second factor. */
  securityKeys: SecurityKeyInfo[];
  backupCodesRemaining: number;
  connectedAccounts: { provider: OAuthProvider; createdAt: string }[];
  /** The app requires two-step verification (a reminder until `twoFactorGraceUntil`, required after). */
  twoFactorRequired?: boolean;
  twoFactorGraceUntil?: string | null;
};

export type SecurityKeyInfo = { id: string; name: string; lastUsedAt: string | null; createdAt: string };
export type PasskeyInfo = { id: string; name: string; synced: boolean; lastUsedAt: string | null; createdAt: string };

/** "admin", "member" or the key of a custom role defined in the dashboard. */
export type OrgRole = string;
export type OrgRoleInfo = { key: string; name: string; description: string | null; permissions: string[]; builtIn: boolean };
export type OrgDomainInfo = {
  id: string; domain: string; verified: boolean; verifiedVia: "dns" | "email" | null; enrollment: "none" | "suggest" | "auto_join"; role: string | null; createdAt: string;
  /** Present until verified: add this TXT record. */
  dns?: { type: "TXT"; name: string; value: string };
};
export type OrgSuggestion = { id: string; name: string; slug: string; domain: string };
/** Instance organization rules; null limits mean unlimited. */
export type OrganizationSettings = {
  enabled: boolean;
  membershipLimit: number | null;
  allowUserCreation: boolean;
  creationLimit: number | null;
  creatorRole: OrgRole;
  defaultRole: OrgRole;
  allowAdminDelete: boolean;
  allowPersonalAccounts: boolean;
};
export type OrgInfo = { id: string; name: string; slug: string; role: OrgRole; /** Permissions of your role in this organization (for showing or hiding UI; enforce on your server). */ permissions?: string[]; requireTwoFactor?: boolean; createdAt?: string };
export type OrgMember = { userId: string; role: OrgRole; email?: string | null; name?: string | null; firstName?: string | null; lastName?: string | null; joinedAt: string };
export type OrgInvitation = { id: string; email: string; role: OrgRole; expiresAt: string; createdAt: string };

export class AuthError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public fields: { path: string; message: string }[] = [],
  ) {
    super(message);
    this.name = "AuthError";
  }
}

/** What a server action needs: proof within `maxAge` seconds at `level` (see `requireRecentAuth` in `@daywalker/auth/server`). */
export type ReverificationNeed = Required<RecentAuthCheck>;
/** The ways this person can prove themselves again. `sms` is the masked phone or null. */
export type ReverificationOptions = { password: boolean; passkey: boolean; totp: boolean; sms: string | null; securityKey: boolean; backupCodes: boolean; emailCode: boolean };

/** Refresh this many seconds before the JWT expires. */
const REFRESH_LEEWAY = 10;

function decodeExp(jwt: string) {
  try {
    const b64 = jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return (JSON.parse(atob(b64)).exp as number) ?? 0;
  } catch {
    return 0;
  }
}

/**
 * Browser client. The JWT is held in memory only (never localStorage). The long-lived
 * refresh token stays in an HttpOnly cookie on the auth service and is never visible to JS.
 */
/** Proof of identity for deleting or exporting. Send what `getReauthRequirements` asks for. */
export type Reauth = { password?: string; code?: string; emailCode?: string };
export type ReauthRequirements = { password: boolean; twoFactor: boolean; emailCode: boolean };

export function createAuthClient(config: Config & { /** Mirror the JWT into a cookie on your domain (default true) */ syncCookie?: boolean; /** Where the device key for session binding is kept (default: IndexedDB). Mostly for tests. */ deviceKeyStore?: DeviceKeyStore }) {
  instanceIdFromKey(config.publishableKey); // fail fast on a bad key
  const base = normalizeOrigin(config.frontendApi);
  const syncCookie = config.syncCookie ?? true;
  assertSatelliteConfig(config);

  let state: AuthState = { isLoaded: false, user: null, sessionId: null };
  let token: { jwt: string; exp: number } | null = null;
  let inflight: Promise<string | null> | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const listeners = new Set<(s: AuthState) => void>();
  const channel = typeof BroadcastChannel !== "undefined" ? new BroadcastChannel("dw-auth") : null;

  function setState(next: Partial<AuthState>) {
    state = { ...state, ...next };
    listeners.forEach((l) => l(state));
  }

  function writeCookies(jwt: string | null, exp = 0) {
    if (!syncCookie || typeof document === "undefined") return;
    const secure = location.protocol === "https:" ? "; Secure" : "";
    if (jwt) {
      const maxAge = Math.max(exp - Math.floor(Date.now() / 1000), 0);
      document.cookie = `${SESSION_COOKIE}=${jwt}; Path=/; Max-Age=${maxAge}; SameSite=Lax${secure}`;
      document.cookie = `${ACTIVE_COOKIE}=1; Path=/; Max-Age=${60 * 60 * 24 * 30}; SameSite=Lax${secure}`;
    } else {
      document.cookie = `${SESSION_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax${secure}`;
      document.cookie = `${ACTIVE_COOKIE}=; Path=/; Max-Age=0; SameSite=Lax${secure}`;
    }
  }

  // Device binding (DPoP): a non-extractable key per browser and instance, created only when the app turns binding on.
  const instanceId = instanceIdFromKey(config.publishableKey);
  const keyStore = config.deviceKeyStore ?? (deviceKeysSupported() ? indexedDbKeyStore : null);
  let deviceKey: Promise<DeviceKey | undefined> | undefined;
  let bindingMode: Promise<"off" | "optional" | "required"> | undefined;
  const CREATES_SESSION = /^(sign_in|sign_up|passkeys\/authenticate\/verify|session\/bind)/;

  function existingDeviceKey() {
    return (deviceKey ??= keyStore ? keyStore.get(instanceId).catch(() => undefined) : Promise.resolve(undefined));
  }

  /** The proof header for this call, or null. Makes the key the first time a session is about to open and the app wants binding. */
  async function proofFor(method: string, path: string, url: string): Promise<string | null> {
    let key = await existingDeviceKey();
    if (!key && keyStore && CREATES_SESSION.test(path)) {
      bindingMode ??= request<{ sessions?: { deviceBinding?: "off" | "optional" | "required" } }>("environment", { method: "GET" }).then((e) => e.sessions?.deviceBinding ?? "off").catch(() => "off" as const);
      if ((await bindingMode) !== "off") {
        key = await generateDeviceKey();
        await keyStore.put(instanceId, key).catch(() => undefined);
        deviceKey = Promise.resolve(key);
      }
    }
    return key ? createDpopProof(key, method, url) : null;
  }

  async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    // The key also goes in the query string: browsers don't send custom headers on CORS preflight
    // requests, and the server needs the key to know which origins this instance allows.
    const url = `${base}/v1/client/${path}${path.includes("?") ? "&" : "?"}pk=${encodeURIComponent(config.publishableKey)}`;
    const proof = await proofFor((init.method ?? "GET").toUpperCase(), path, url);
    const res = await fetch(url, {
      ...init,
      credentials: "include",
      headers: { "content-type": "application/json", "x-publishable-key": config.publishableKey, ...(proof ? { dpop: proof } : {}) },
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
      const e = body.error ?? {};
      throw new AuthError(res.status, e.code ?? "unknown", e.message ?? "Request failed", e.fields);
    }
    return body as T;
  }

  function acceptToken(jwt: string) {
    const exp = decodeExp(jwt);
    token = { jwt, exp };
    writeCookies(jwt, exp);
    clearTimeout(timer);
    const delay = Math.max((exp - REFRESH_LEEWAY) * 1000 - Date.now(), 1000);
    // Keep the token warm while the tab is open; skip work in background tabs.
    timer = setTimeout(() => {
      if (typeof document === "undefined" || document.visibilityState === "visible") void getToken({ force: true });
    }, delay);
  }

  const readCookie = (name: string) => (typeof document === "undefined" ? undefined : document.cookie.split("; ").find((c) => c.startsWith(`${name}=`))?.slice(name.length + 1));

  /**
   * Satellite domains: when the service's cookie isn't visible from here (third-party cookies blocked), the session is
   * learned through the redirect handshake that the Next.js `authProxy` serves at /__daywalker/sync. At most once per
   * 30 seconds, and not right after a sync found nobody signed in.
   */
  function satelliteResync() {
    if (!config.isSatellite || typeof window === "undefined" || readCookie(SATELLITE_SIGNED_OUT_COOKIE)) return;
    try {
      const last = Number(sessionStorage.getItem("dw_sat_sync") ?? 0);
      if (Date.now() - last < 30_000) return;
      sessionStorage.setItem("dw_sat_sync", String(Date.now()));
    } catch {
      return;
    }
    window.location.assign(`${SATELLITE_SYNC_PATH}?to=${encodeURIComponent(window.location.href)}`);
  }

  /** The token the proxy synced into this domain's cookie, if it is still valid (satellites only). */
  function syncedToken() {
    const jwt = readCookie(SESSION_COOKIE);
    if (!jwt) return null;
    try {
      const p = JSON.parse(atob(jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))) as { exp?: number; sid?: string };
      return p.exp && p.sid && p.exp > Date.now() / 1000 + 5 ? { jwt, exp: p.exp, sid: p.sid } : null;
    } catch {
      return null;
    }
  }

  function clearLocal() {
    token = null;
    clearTimeout(timer);
    writeCookies(null);
    setState({ isLoaded: true, user: null, sessionId: null, twoFactorSetupRequired: false });
  }

  /** Returns a valid JWT, refreshing if needed. Concurrent callers share one request. */
  async function getToken(opts: { force?: boolean } = {}): Promise<string | null> {
    if (!opts.force && token && token.exp - REFRESH_LEEWAY > Date.now() / 1000) return token.jwt;
    if (!state.sessionId && state.isLoaded) return null;
    inflight ??= request<{ jwt: string }>("session/token", { method: "POST" })
      .then((r) => {
        acceptToken(r.jwt);
        return r.jwt;
      })
      .catch((e) => {
        if (e instanceof AuthError && e.status === 401) {
          clearLocal();
          satelliteResync();
        }
        if (e instanceof AuthError && e.code === "two_factor_setup_required") setState({ twoFactorSetupRequired: true });
        return null;
      })
      .finally(() => (inflight = null));
    return inflight;
  }

  async function load() {
    const r = await request<{ session: { id: string; deviceBound?: boolean; deviceBinding?: "off" | "optional" | "required"; deviceBindable?: boolean } | null; user: User | null }>("session", { method: "GET" }).catch(
      () => ({ session: null, user: null }),
    );
    if (!r.session) {
      const synced = config.isSatellite ? syncedToken() : null;
      if (synced) {
        // The service's own cookie isn't visible from this domain, but the handshake gave us a token: signed in, minus the profile.
        token = { jwt: synced.jwt, exp: synced.exp };
        setState({ isLoaded: true, user: null, sessionId: synced.sid });
        return state;
      }
      clearLocal();
      satelliteResync();
      return state;
    }
    // A sign-in that came back through a redirect (social, SSO, link) couldn't carry a proof: bind it now.
    if (r.session.deviceBinding && r.session.deviceBinding !== "off" && !r.session.deviceBound && r.session.deviceBindable)
      await request("session/bind", { method: "POST" }).catch(() => undefined);
    setState({ isLoaded: true, user: r.user, sessionId: r.session.id });
    await getToken({ force: true });
    return state;
  }

  type Completed = { status: "complete"; user: User; sessionId: string; jwt: string | null; twoFactorSetupRequired?: boolean };

  function finishSignIn(r: Completed): { status: "complete"; user: User } | { status: "needs_two_factor_setup"; user: User } {
    if (r.jwt) acceptToken(r.jwt);
    setState({ isLoaded: true, user: r.user, sessionId: r.sessionId, twoFactorSetupRequired: !r.jwt && r.twoFactorSetupRequired === true });
    channel?.postMessage("signed-in");
    return !r.jwt && r.twoFactorSetupRequired ? { status: "needs_two_factor_setup", user: r.user } : { status: "complete", user: r.user };
  }

  async function signIn(input: { email: string; password: string; /** Turnstile answer, when the app has the human check on (see getEnvironment().captcha). */ captchaToken?: string }): Promise<SignInResult> {
    const r = await request<Completed | { status: "needs_second_factor" }>("sign_in", { method: "POST", body: JSON.stringify(input) });
    return r.status === "needs_second_factor" ? r : finishSignIn(r);
  }

  /**
   * Passwordless sign-in, step 1: email a 6-digit code and a one-time link. Resolves the same way
   * whether or not the email has an account. `redirectUrl` is where the link lands after sign-in
   * (must be an allowed origin). Needs "Email sign-in" turned on for the instance.
   */
  async function sendSignInCode(input: { email: string; redirectUrl?: string; /** Turnstile answer, when the app has the human check on. */ captchaToken?: string }) {
    await request("sign_in/email_code", { method: "POST", body: JSON.stringify(input) });
  }

  /** Passwordless sign-in, step 2: the code from the email. */
  async function signInWithEmailCode(input: { email: string; code: string }): Promise<SignInResult> {
    const r = await request<Completed | { status: "needs_second_factor" }>("sign_in/email_code/verify", { method: "POST", body: JSON.stringify(input) });
    return r.status === "needs_second_factor" ? r : finishSignIn(r);
  }

  /** Completes a sign-in link: pass the `token` from the link's URL fragment (#token=...). */
  async function signInWithMagicLink(token: string): Promise<SignInResult & { redirectUrl: string | null }> {
    const r = await request<(Completed | { status: "needs_second_factor" }) & { redirectUrl: string | null }>("sign_in/magic_link", { method: "POST", body: JSON.stringify({ token }) });
    return r.status === "needs_second_factor" ? r : { ...finishSignIn(r), redirectUrl: r.redirectUrl };
  }

  /** Uses the one-time token from the "account locked" email (URL fragment `#token=`). The user then signs in as usual. */
  async function unlockAccount(token: string) {
    return request<{ unlocked: true }>("unlock", { method: "POST", body: JSON.stringify({ token }) });
  }

  /** Uses the one-time token from the "scheduled for deletion" email (URL fragment `#token=`). The user then signs in as usual. */
  async function cancelAccountDeletion(token: string) {
    return request<{ canceled: true }>("cancel_deletion", { method: "POST", body: JSON.stringify({ token }) });
  }

  /** What to ask for before deleting or exporting: the password, a 2FA code, or (if neither exists) an emailed code. */
  async function getReauthRequirements() {
    return request<ReauthRequirements>("me/reauth_code");
  }

  /** Emails a confirmation code. Only for accounts with no password and no two-factor. */
  async function sendReauthCode() {
    await request<{ sent: true }>("me/reauth_code", { method: "POST" });
  }

  /** Schedules the account for deletion and signs out everywhere. Re-authentication is required. */
  async function deleteAccount(reauth: Reauth) {
    return request<{ scheduledFor: string; deleted: boolean }>("me/delete", { method: "POST", body: JSON.stringify(reauth) });
  }

  /** The user's data as an object (decrypted for them). Re-authentication is required; 3 per hour. */
  async function exportData(reauth: Reauth) {
    return request<Record<string, unknown>>("me/export", { method: "POST", body: JSON.stringify(reauth) });
  }

  /** Does this email's domain sign in through the company's identity provider (SAML SSO)? */
  async function checkSSO(email: string) {
    return request<{ sso: boolean; connectionName: string | null; required: boolean }>("sso/check", { method: "POST", body: JSON.stringify({ email }) });
  }

  /** Full-page redirect to the company's sign-in page, then back to `redirectUrl` (default: current page). */
  function signInWithSSO(email: string, redirectUrl?: string, opts: { legalAccepted?: boolean } = {}) {
    const u = new URL(`${base}/v1/client/sso/start`);
    u.searchParams.set("pk", config.publishableKey);
    u.searchParams.set("email", email);
    u.searchParams.set("redirect_url", redirectUrl ?? window.location.href);
    if (opts.legalAccepted) u.searchParams.set("legal_accepted", "1");
    window.location.assign(u.toString());
  }

  /** Second step of sign-in for accounts with 2FA: a 6-digit authenticator code or a backup code. */
  async function completeSecondFactor(code: string, method?: "totp" | "sms") {
    return finishSignIn(await request<Completed>("sign_in/second_factor", { method: "POST", body: JSON.stringify({ code, method }) }));
  }

  /** During sign-in: which second factors the account has. `sms` is the masked phone or null. */
  function getSecondFactorOptions() {
    return request<{ totp: boolean; sms: string | null; securityKey: boolean; backupCodes: boolean }>("sign_in/second_factor/options", { method: "POST" });
  }

  /** During sign-in: text a code to the account's phone, then call completeSecondFactor(code, "sms"). */
  function sendSecondFactorSms() {
    return request<{ phone: string }>("sign_in/second_factor/sms", { method: "POST" });
  }

  /** Add a phone for SMS two-factor (international format). Pass a current code if two-factor is already on. */
  function startSmsSetup(phone: string, currentCode?: string) {
    return request<{ phone: string }>("mfa/sms", { method: "POST", body: JSON.stringify({ phone, code: currentCode }) });
  }

  /** Confirm the phone with the texted code. Returns new backup codes when this turns two-factor on (else []). */
  async function confirmSmsSetup(code: string) {
    const r = await request<{ backupCodes: string[] }>("mfa/sms/verify", { method: "POST", body: JSON.stringify({ code }) });
    if (state.user) setState({ user: { ...state.user, twoFactorEnabled: true } });
    return r.backupCodes;
  }

  /** Text a code to the signed-in user's phone, e.g. to confirm removing it. */
  function sendSmsCode() {
    return request<{ phone: string }>("mfa/sms/send", { method: "POST" });
  }

  /** Remove the two-factor phone. Needs a current code (authenticator, texted or backup). */
  async function removeSmsPhone(code?: string) {
    await request("mfa/sms/remove", { method: "POST", body: JSON.stringify({ code }) });
  }

  /** 2FA setup, step 1: returns `uri` (render it as a QR code) and `secret` (for manual entry). */
  function startTotpSetup(currentCode?: string) {
    return request<{ secret: string; uri: string }>("mfa/totp", { method: "POST", body: JSON.stringify({ code: currentCode }) });
  }

  /** 2FA setup, step 2: confirm with a code from the app. Returns backup codes; show them once. */
  async function confirmTotpSetup(code: string) {
    const r = await request<{ backupCodes: string[] }>("mfa/totp/verify", { method: "POST", body: JSON.stringify({ code }) });
    if (state.user) setState({ user: { ...state.user, twoFactorEnabled: true } });
    return r.backupCodes;
  }

  /**
   * Confirm with a security key instead of typing a code. The browser asks the person to touch it. For the next two
   * minutes, ONE sensitive change (adding or removing a factor, turning two-factor off, new backup codes) can then be
   * made by calling it without a code.
   */
  async function confirmWithSecurityKey() {
    const optionsJSON = await request<Parameters<typeof startAuthentication>[0]["optionsJSON"]>("mfa/security_keys/confirm/options", { method: "POST" });
    let response;
    try {
      response = await startAuthentication({ optionsJSON });
    } catch (e) {
      securityKeyError(e);
    }
    await request("mfa/security_keys/confirm", { method: "POST", body: JSON.stringify({ response }) });
  }

  /** Turn 2FA off. Needs a current authenticator or backup code (or call `confirmWithSecurityKey()` first and pass none). */
  async function disableTwoFactor(code?: string) {
    await request("mfa/totp/disable", { method: "POST", body: JSON.stringify({ code }) });
    if (state.user) setState({ user: { ...state.user, twoFactorEnabled: false } });
  }

  /** Replace all backup codes. Needs a current code. */
  async function regenerateBackupCodes(code?: string) {
    return (await request<{ backupCodes: string[] }>("mfa/backup_codes", { method: "POST", body: JSON.stringify({ code }) })).backupCodes;
  }

  /** `legalAccepted` is required when the instance requires terms acceptance (see getEnvironment().legal). */
  async function signUp(input: { email: string; password: string; firstName?: string; lastName?: string; legalAccepted?: boolean; /** Turnstile answer, when the app has the human check on (see getEnvironment().captcha). */ captchaToken?: string }) {
    const r = await request<{ user: User; sessionId: string; jwt: string | null; twoFactorSetupRequired?: boolean }>("sign_up", { method: "POST", body: JSON.stringify(input) });
    if (r.jwt) acceptToken(r.jwt);
    setState({ isLoaded: true, user: r.user, sessionId: r.sessionId, twoFactorSetupRequired: !r.jwt && r.twoFactorSetupRequired === true });
    channel?.postMessage("signed-in");
    return r.user;
  }

  /**
   * Sign out here and in other tabs. If the person signed in through company SSO and the connection
   * has single logout on, the browser then goes to the identity provider to sign out there too, and
   * comes back to `redirectUrl` (or the hosted sign-in page). Pass `singleLogout: false` to skip that.
   */
  async function signOut(opts: { redirectUrl?: string; singleLogout?: boolean } = {}) {
    const r = await request<{ ssoLogoutUrl?: string }>("session", { method: "DELETE", body: JSON.stringify({ redirectUrl: opts.redirectUrl && typeof window !== "undefined" ? new URL(opts.redirectUrl, window.location.href).href : opts.redirectUrl }) }).catch(() => null);
    clearLocal();
    channel?.postMessage("signed-out"); // other tabs drop their in-memory token too
    if (r?.ssoLogoutUrl && opts.singleLogout !== false && typeof window !== "undefined" && /^https?:\/\//.test(r.ssoLogoutUrl)) {
      window.location.assign(r.ssoLogoutUrl);
      return { redirecting: true };
    }
    return { redirecting: false };
  }

  channel?.addEventListener("message", (e) => {
    if (e.data === "signed-out") clearLocal();
    if (e.data === "signed-in") void load();
  });

  /** Emails a 6-digit code to the signed-in user's primary address. */
  async function sendVerificationCode() {
    await request("email/send_code", { method: "POST" });
  }

  /** Confirms the code; the user's email is marked verified. */
  async function verifyEmail(code: string) {
    const r = await request<{ user: User }>("email/verify", { method: "POST", body: JSON.stringify({ code }) });
    setState({ user: r.user });
    return r.user;
  }

  /** Starts a reset. Resolves the same way whether or not the email has an account. */
  async function requestPasswordReset(email: string, opts: { /** Turnstile answer, when the app has the human check on. */ captchaToken?: string } = {}) {
    await request("password/forgot", { method: "POST", body: JSON.stringify({ email, ...opts }) });
  }

  /** Sets a new password with the emailed code. Signs the user out on every device. */
  async function resetPassword(input: { email: string; code: string; password: string }) {
    await request("password/reset", { method: "POST", body: JSON.stringify(input) });
    clearLocal();
    channel?.postMessage("signed-out");
  }

  /**
   * Full-page redirect to Google/GitHub. The user comes back to `redirectUrl` signed in.
   * `redirectUrl` must be on your instance's allowed origins (or it's ignored).
   */
  function signInWithOAuth(provider: OAuthProvider, redirectUrl?: string, opts: { legalAccepted?: boolean } = {}) {
    const u = new URL(`${base}/v1/client/oauth/${provider}/start`);
    u.searchParams.set("pk", config.publishableKey);
    // Needed only when this creates a new account on an instance that requires terms.
    if (opts.legalAccepted) u.searchParams.set("legal_accepted", "1");
    const back = redirectUrl ?? (typeof window !== "undefined" ? window.location.href : undefined);
    if (back) u.searchParams.set("redirect_url", back);
    window.location.assign(u.toString());
  }

  /** Public settings for this instance, e.g. which OAuth providers are enabled. */
  function getEnvironment() {
    return request<{
      name: string;
      oauthProviders: OAuthProvider[];
      /** Button labels; a custom OpenID Connect provider has its own name. */
      oauthProviderLabels: Partial<Record<OAuthProvider, string>>;
      passwordMinLength: number;
      emailCodeSignIn: boolean;
      /** New people can create an account with an email and a passkey (see `startPasskeySignUp`). */
      passkeySignUp: boolean;
      /** At least one SAML SSO connection is enabled. */
      ssoEnabled: boolean;
      /** Users can add a phone for SMS two-factor. */
      smsSecondFactor: boolean;
      legal: { required: boolean; termsUrl: string | null; privacyUrl: string | null; version: string };
      /** Cloudflare Turnstile: when set, sign-up, sign-in, email codes and password reset need a `captchaToken`. */
      captcha: { provider: "turnstile"; siteKey: string } | null;
      /** Organization rules the instance enforces (set in the dashboard under Organizations). */
      organizations: OrganizationSettings;
      /** Session rules (set in the dashboard under Sessions). */
      sessions: { multiSession: boolean; inactivityTimeoutMinutes: number | null };
    }>("environment", { method: "GET" });
  }

  /** Update the signed-in user's name. Pass null to clear a field. */
  async function updateProfile(input: { firstName?: string | null; lastName?: string | null }) {
    const r = await request<{ user: User }>("me", { method: "PATCH", body: JSON.stringify(input) });
    setState({ user: r.user });
    return r.user;
  }

  /** Change password. Requires the current one; signs out all other sessions. */
  function changePassword(input: { currentPassword: string; newPassword: string }) {
    return request<{ changed: true; otherSessionsSignedOut: number }>("password/change", { method: "POST", body: JSON.stringify(input) });
  }

  /** Password / 2FA / connected-account status for a settings screen. */
  function getSecurity() {
    return request<SecurityInfo>("me/security", { method: "GET" });
  }

  /** The user's active sessions across devices. */
  async function listSessions() {
    return (await request<{ sessions: SessionInfo[] }>("sessions", { method: "GET" })).sessions;
  }

  /** API keys the signed-in user holds, or an organization's (needs permission to manage it). Only when the app enabled them. */
  async function listApiKeys(opts: { orgId?: string } = {}) {
    const q = opts.orgId ? `?orgId=${encodeURIComponent(opts.orgId)}` : "";
    return (await request<{ data: ApiKeyInfo[] }>(`api_keys${q}`, { method: "GET" })).data;
  }

  /** Creates an API key. `key` is returned once; show it to the user and don't store it. Needs a recent sign-in. */
  async function createApiKey(input: { name: string; scopes?: string[]; expiresInDays?: number; orgId?: string }) {
    return request<ApiKeyInfo & { key: string }>("api_keys", { method: "POST", body: JSON.stringify(input) });
  }

  async function revokeApiKey(keyId: string) {
    return request<ApiKeyInfo>(`api_keys/${encodeURIComponent(keyId)}`, { method: "DELETE" });
  }

  /** Sign out another device. */
  async function revokeSession(sessionId: string) {
    await request(`sessions/${encodeURIComponent(sessionId)}/revoke`, { method: "POST" });
  }

  /** Sign out every device except this one. */
  async function revokeOtherSessions() {
    return (await request<{ signedOut: number }>("sessions/revoke_others", { method: "POST" })).signedOut;
  }

  /** True when this browser can create and use passkeys. */
  function passkeysSupported() {
    return typeof window !== "undefined" && browserSupportsWebAuthn();
  }

  /** Browser-side failures (cancelled prompt, no support) become AuthErrors with stable codes. */
  function webauthnError(e: unknown): never {
    if (e instanceof AuthError) throw e;
    const name = (e as { name?: string })?.name;
    if (name === "NotAllowedError" || name === "AbortError") throw new AuthError(0, "passkey_cancelled", "The passkey prompt was closed or timed out");
    if (name === "InvalidStateError") throw new AuthError(0, "passkey_exists", "This device already has a passkey for this account");
    throw new AuthError(0, "passkey_unsupported", "This browser couldn't use a passkey");
  }

  /**
   * Adds a passkey for the signed-in user. Requires a recent sign-in (15 minutes);
   * otherwise rejects with code `reauth_required`.
   */
  async function registerPasskey(name?: string) {
    const optionsJSON = await request<Parameters<typeof startRegistration>[0]["optionsJSON"]>("passkeys/register/options", { method: "POST" });
    let response;
    try {
      response = await startRegistration({ optionsJSON });
    } catch (e) {
      webauthnError(e);
    }
    return request<{ id: string }>("passkeys/register/verify", { method: "POST", body: JSON.stringify({ response, name }) });
  }

  /** True when the browser can offer passkeys in the email field's autofill list (conditional UI). */
  async function passkeyAutofillSupported() {
    if (typeof window === "undefined") return false;
    try {
      return await browserSupportsWebAuthnAutofill();
    } catch {
      return false;
    }
  }

  /**
   * Conditional UI: arms the browser so saved passkeys appear in the autofill list of an input with
   * `autocomplete="username webauthn"`. Resolves when the person picks one (and rejects with code
   * `passkey_cancelled` if it is stopped). Starting any other passkey prompt, or `cancelPasskeyAutofill()`,
   * stops it. Challenges last five minutes, so call this again after a long wait; `<SignIn/>` does that for you.
   */
  async function signInWithPasskeyAutofill(): Promise<SignInResult> {
    const optionsJSON = await request<Parameters<typeof startAuthentication>[0]["optionsJSON"]>("passkeys/authenticate/options", { method: "POST" });
    let response;
    try {
      response = await startAuthentication({ optionsJSON, useBrowserAutofill: true });
    } catch (e) {
      webauthnError(e);
    }
    return finishSignIn(await request<Completed>("passkeys/authenticate/verify", { method: "POST", body: JSON.stringify({ response }) }));
  }

  /** Stops a pending `signInWithPasskeyAutofill()`. */
  function cancelPasskeyAutofill() {
    WebAuthnAbortService.cancelCeremony();
  }

  /**
   * Passkey-first sign-up, step 1: emails a 6-digit code to a new address. Resolves the same way whether or not
   * the address already has an account. Needs "Sign up with a passkey" turned on (`getEnvironment().passkeySignUp`).
   */
  async function startPasskeySignUp(input: { email: string; firstName?: string; lastName?: string; legalAccepted?: boolean; captchaToken?: string }) {
    await request("sign_up/passkey/start", { method: "POST", body: JSON.stringify(input) });
  }

  /**
   * Passkey-first sign-up, step 2: checks the emailed code, then asks the browser to create a passkey and
   * creates the account (no password, email already verified) and signs it in. Nothing exists until the passkey is made.
   */
  async function completePasskeySignUp(input: { email: string; code: string; name?: string }) {
    const { token, options } = await request<{ token: string; options: Parameters<typeof startRegistration>[0]["optionsJSON"] }>("sign_up/passkey/verify", { method: "POST", body: JSON.stringify({ email: input.email, code: input.code }) });
    let response;
    try {
      response = await startRegistration({ optionsJSON: options });
    } catch (e) {
      webauthnError(e);
    }
    const r = await request<Completed>("sign_up/passkey/complete", { method: "POST", body: JSON.stringify({ response, token, name: input.name }) });
    return finishSignIn({ ...r, status: "complete" });
  }

  /** Sign in with a passkey. No email needed: the user picks their passkey in the browser prompt. */
  async function signInWithPasskey(): Promise<SignInResult> {
    const optionsJSON = await request<Parameters<typeof startAuthentication>[0]["optionsJSON"]>("passkeys/authenticate/options", { method: "POST" });
    let response;
    try {
      response = await startAuthentication({ optionsJSON });
    } catch (e) {
      webauthnError(e);
    }
    return finishSignIn(await request<Completed>("passkeys/authenticate/verify", { method: "POST", body: JSON.stringify({ response }) }));
  }

  async function listPasskeys() {
    return (await request<{ passkeys: PasskeyInfo[] }>("passkeys", { method: "GET" })).passkeys;
  }

  async function renamePasskey(id: string, name: string) {
    await request(`passkeys/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ name }) });
  }

  async function deletePasskey(id: string) {
    await request(`passkeys/${encodeURIComponent(id)}`, { method: "DELETE" });
  }

  function securityKeyError(e: unknown): never {
    if (e instanceof AuthError) throw e;
    const name = (e as { name?: string })?.name;
    if (name === "NotAllowedError" || name === "AbortError") throw new AuthError(0, "security_key_cancelled", "The security key prompt was closed or timed out");
    if (name === "InvalidStateError") throw new AuthError(0, "security_key_exists", "This security key is already registered");
    throw new AuthError(0, "security_key_unsupported", "This browser couldn't use a security key");
  }

  /**
   * Adds a security key (YubiKey and similar) as a second factor. Needs a recent sign-in, and a current
   * code (`currentCode`) if two-factor is already on. Returns backup codes (shown once) when this turned two-factor on.
   */
  async function addSecurityKey(opts: { name?: string; currentCode?: string } = {}) {
    const optionsJSON = await request<Parameters<typeof startRegistration>[0]["optionsJSON"]>("mfa/security_keys/register/options", { method: "POST", body: JSON.stringify({ code: opts.currentCode }) });
    let response;
    try {
      response = await startRegistration({ optionsJSON });
    } catch (e) {
      securityKeyError(e);
    }
    const r = await request<{ id: string; backupCodes: string[] }>("mfa/security_keys/register/verify", { method: "POST", body: JSON.stringify({ response, name: opts.name }) });
    if (state.user) setState({ user: { ...state.user, twoFactorEnabled: true } });
    return r;
  }

  async function listSecurityKeys() {
    return (await request<{ securityKeys: SecurityKeyInfo[] }>("mfa/security_keys", { method: "GET" })).securityKeys;
  }

  async function renameSecurityKey(id: string, name: string) {
    await request(`mfa/security_keys/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify({ name }) });
  }

  /** Remove a security key. Needs a current code (authenticator, texted or backup). */
  async function removeSecurityKey(id: string, code?: string) {
    await request(`mfa/security_keys/${encodeURIComponent(id)}/remove`, { method: "POST", body: JSON.stringify({ code }) });
  }

  /** During sign-in: finish with a security key. The browser asks the person to touch it. */
  async function completeSecondFactorWithSecurityKey() {
    const optionsJSON = await request<Parameters<typeof startAuthentication>[0]["optionsJSON"]>("sign_in/second_factor/security_key", { method: "POST" });
    let response;
    try {
      response = await startAuthentication({ optionsJSON });
    } catch (e) {
      securityKeyError(e);
    }
    return finishSignIn(await request<Completed>("sign_in/second_factor", { method: "POST", body: JSON.stringify({ response }) }));
  }

  const orgPath = (id: string, rest = "") => `organizations/${encodeURIComponent(id)}${rest}`;
  const json = (body: unknown, method = "POST") => ({ method, body: JSON.stringify(body) });

  /** Organizations you belong to, with your role in each. */
  async function listOrganizations() {
    return (await request<{ organizations: OrgInfo[] }>("organizations", { method: "GET" })).organizations;
  }

  /** Roles you can pick from (built-in and custom), with their permissions. */
  async function listOrganizationRoles() {
    return (await request<{ roles: OrgRoleInfo[] }>("organization_roles", { method: "GET" })).roles;
  }

  /** Domains this organization claimed (admins). Unverified ones include the DNS record to add. */
  async function listOrgDomains(orgId: string) {
    return (await request<{ domains: OrgDomainInfo[] }>(orgPath(orgId, "/domains"), { method: "GET" })).domains;
  }
  async function addOrgDomain(orgId: string, domain: string) {
    return (await request<{ domain: OrgDomainInfo }>(orgPath(orgId, "/domains"), json({ domain }))).domain;
  }
  /** Looks for the TXT record. Fails with `verification_failed` until DNS has it. */
  async function verifyOrgDomainDns(orgId: string, domainId: string) {
    return (await request<{ domain: OrgDomainInfo }>(orgPath(orgId, `/domains/${encodeURIComponent(domainId)}/verify`), json({ method: "dns" }))).domain;
  }
  /** Emails a code to admin@, postmaster@ etc. at the domain. */
  async function sendOrgDomainEmail(orgId: string, domainId: string, mailbox: "admin" | "administrator" | "postmaster" | "webmaster" | "hostmaster") {
    return request<{ sentTo: string }>(orgPath(orgId, `/domains/${encodeURIComponent(domainId)}/verify`), json({ method: "email", mailbox }));
  }
  async function verifyOrgDomainEmail(orgId: string, domainId: string, code: string) {
    return (await request<{ domain: OrgDomainInfo }>(orgPath(orgId, `/domains/${encodeURIComponent(domainId)}/verify`), json({ method: "email", code }))).domain;
  }
  /** `enrollment`: "none", "suggest" (members of the domain are offered the organization) or "auto_join". */
  async function updateOrgDomain(orgId: string, domainId: string, input: { enrollment?: "none" | "suggest" | "auto_join"; role?: string | null }) {
    return (await request<{ domain: OrgDomainInfo }>(orgPath(orgId, `/domains/${encodeURIComponent(domainId)}`), json(input, "PATCH"))).domain;
  }
  async function removeOrgDomain(orgId: string, domainId: string) {
    await request(orgPath(orgId, `/domains/${encodeURIComponent(domainId)}`), { method: "DELETE" });
  }
  /** Organizations offered to you because a verified email of yours is at their verified domain. */
  async function listOrgSuggestions() {
    return (await request<{ suggestions: OrgSuggestion[] }>("organizations/suggestions", { method: "GET" })).suggestions;
  }
  async function acceptOrgSuggestion(orgId: string) {
    return (await request<{ organization: OrgInfo }>(`organizations/suggestions/${encodeURIComponent(orgId)}/accept`, json({}))).organization;
  }

  /** Create an organization. You become its admin. */
  async function createOrganization(name: string) {
    return (await request<{ organization: OrgInfo }>("organizations", json({ name }))).organization;
  }

  async function renameOrganization(orgId: string, name: string) {
    await request(orgPath(orgId), json({ name }, "PATCH"));
  }

  /** Admins: require two-step verification for this organization's members. You need it on yourself first. */
  async function setOrganizationTwoFactor(orgId: string, required: boolean) {
    await request(orgPath(orgId), json({ requireTwoFactor: required }, "PATCH"));
  }

  async function deleteOrganization(orgId: string) {
    await request(orgPath(orgId), { method: "DELETE" });
  }

  async function listOrgMembers(orgId: string) {
    return (await request<{ members: OrgMember[] }>(orgPath(orgId, "/members"), { method: "GET" })).members;
  }

  async function changeOrgRole(orgId: string, userId: string, role: OrgRole) {
    await request(orgPath(orgId, `/members/${encodeURIComponent(userId)}`), json({ role }, "PATCH"));
  }

  /** Remove a member. Pass your own user ID (or "me") to leave. */
  async function removeOrgMember(orgId: string, userId: string) {
    await request(orgPath(orgId, `/members/${encodeURIComponent(userId)}`), { method: "DELETE" });
  }

  async function inviteToOrg(orgId: string, email: string, role: OrgRole = "member") {
    return (await request<{ invitation: OrgInvitation }>(orgPath(orgId, "/invitations"), json({ email, role }))).invitation;
  }

  async function listOrgInvitations(orgId: string) {
    return (await request<{ invitations: OrgInvitation[] }>(orgPath(orgId, "/invitations"), { method: "GET" })).invitations;
  }

  async function revokeOrgInvitation(orgId: string, invitationId: string) {
    await request(orgPath(orgId, `/invitations/${encodeURIComponent(invitationId)}`), { method: "DELETE" });
  }

  /** What an invite link is for (org name and role). Works while signed out. */
  async function previewInvitation(token: string) {
    return request<{ orgName: string; role: OrgRole }>("invitations/preview", json({ token }));
  }

  async function acceptInvitation(token: string) {
    return (await request<{ organization: OrgInfo }>("invitations/accept", json({ token }))).organization;
  }

  /** Switch the active organization (null = personal). Refreshes the JWT so its org claims update. */
  async function setActiveOrganization(orgId: string | null) {
    const r = await request<{ jwt: string }>("session/active_org", json({ orgId }));
    token = null; // force the next getToken() to pick up the new claims
    await getToken({ force: true });
    return r;
  }

  // ---------- Step-up (reverification) ----------

  let reverifyHandler: ((need: ReverificationNeed) => Promise<boolean>) | null = null;

  /**
   * Registers the function `authFetch` calls when your server answers 403 `reverification_required`: show a prompt,
   * resolve true once the person proved themselves (or false to give up). `<AuthProvider>` registers its own prompt;
   * use this for a custom UI. Returns a function that unregisters it.
   */
  function setReverificationHandler(fn: ((need: ReverificationNeed) => Promise<boolean>) | null) {
    reverifyHandler = fn;
    return () => {
      if (reverifyHandler === fn) reverifyHandler = null;
    };
  }

  /** Runs the registered reverification prompt (see `setReverificationHandler`) and resolves true once the person proved themselves. False when there is no prompt or they gave up. */
  function requestReverification(need: ReverificationNeed) {
    return reverifyHandler ? reverifyHandler(need) : Promise.resolve(false);
  }

  /** Which ways the signed-in person can prove themselves again (so a prompt only offers real choices). */
  function getReverificationOptions() {
    return request<ReverificationOptions>("session/reverify", { method: "GET" });
  }

  async function reverifyRequest(path: string, body: unknown) {
    const r = await request<{ verified: true; jwt: string }>(path, json(body));
    acceptToken(r.jwt); // the new token carries the fresh ages
  }

  /** Prove the password again. */
  function reverifyWithPassword(password: string) {
    return reverifyRequest("session/reverify", { factor: "password", password });
  }

  /** Prove a second factor again: an authenticator, texted or backup code. */
  function reverifyWithCode(code: string, method?: "totp" | "sms") {
    return reverifyRequest("session/reverify", { factor: "code", code, method });
  }

  /** For accounts with no password and no two-factor: emails a code (then call `reverifyWithEmailCode`). */
  function sendReverificationEmailCode() {
    return request("me/reauth_code", { method: "POST" });
  }

  function reverifyWithEmailCode(code: string) {
    return reverifyRequest("session/reverify", { factor: "email_code", code });
  }

  /** Touch a registered security key: counts as the second factor. */
  async function reverifyWithSecurityKey() {
    await confirmWithSecurityKey();
    await reverifyRequest("session/reverify", { factor: "security_key" });
  }

  /** Use a passkey: it is a device plus a biometric or PIN, so it counts as both factors. */
  async function reverifyWithPasskey() {
    const optionsJSON = await request<Parameters<typeof startAuthentication>[0]["optionsJSON"]>("session/reverify/passkey/options", { method: "POST" });
    let response;
    try {
      response = await startAuthentication({ optionsJSON });
    } catch (e) {
      webauthnError(e);
    }
    await reverifyRequest("session/reverify/passkey", { response });
  }

  /**
   * `fetch` that attaches `Authorization: Bearer <jwt>` for calls to your own backend. If your server answers
   * 403 `reverification_required` (see `requireRecentAuth`), it runs the reverification prompt and retries once with
   * a fresh token. A request body that is a stream can't be replayed, so the retry is skipped for those.
   */
  async function authFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
    const send = async () => {
      const jwt = await getToken();
      const headers = new Headers(init.headers);
      if (jwt) headers.set("authorization", `Bearer ${jwt}`);
      return fetch(input, { ...init, headers });
    };
    const res = await send();
    if (res.status !== 403 || !reverifyHandler || (typeof ReadableStream !== "undefined" && init.body instanceof ReadableStream)) return res;
    const need = await res.clone().json().then((b) => (b?.error?.code === "reverification_required" ? (b.error.reverification as ReverificationNeed) : null)).catch(() => null);
    if (!need || !(await reverifyHandler(need))) return res;
    return send();
  }

  /** URL of the hosted sign-in / sign-up page that returns to `redirectUrl` afterwards. */
  function hostedUrl(page: "sign-in" | "sign-up" | "forgot-password" | "account" | "unauthorized-sign-in" | "organization" | "create-organization", redirectUrl?: string, opts: { organizationId?: string } = {}) {
    const u = new URL(`${config.hostedDomain ? normalizeOrigin(config.hostedDomain) : base}/${page}`);
    if (!config.hostedDomain) u.searchParams.set("pk", config.publishableKey);
    if (redirectUrl) u.searchParams.set("redirect_url", redirectUrl);
    if (opts.organizationId) u.searchParams.set("org", opts.organizationId);
    return u.toString();
  }

  return {
    get state() {
      return state;
    },
    subscribe(fn: (s: AuthState) => void) {
      listeners.add(fn);
      return () => void listeners.delete(fn);
    },
    load,
    getToken,
    signIn,
    checkSSO,
    signInWithSSO,
    sendSignInCode,
    signInWithEmailCode,
    signInWithMagicLink,
    unlockAccount,
    cancelAccountDeletion,
    getReauthRequirements,
    sendReauthCode,
    deleteAccount,
    exportData,
    signUp,
    signOut,
    authFetch,
    setReverificationHandler,
    requestReverification,
    getReverificationOptions,
    reverifyWithPassword,
    reverifyWithCode,
    sendReverificationEmailCode,
    reverifyWithEmailCode,
    reverifyWithSecurityKey,
    reverifyWithPasskey,
    hostedUrl,
    sendVerificationCode,
    verifyEmail,
    requestPasswordReset,
    resetPassword,
    signInWithOAuth,
    getEnvironment,
    completeSecondFactor,
    getSecondFactorOptions,
    sendSecondFactorSms,
    startSmsSetup,
    confirmSmsSetup,
    sendSmsCode,
    removeSmsPhone,
    addSecurityKey,
    listSecurityKeys,
    renameSecurityKey,
    removeSecurityKey,
    completeSecondFactorWithSecurityKey,
    confirmWithSecurityKey,
    startTotpSetup,
    confirmTotpSetup,
    disableTwoFactor,
    regenerateBackupCodes,
    updateProfile,
    changePassword,
    getSecurity,
    listSessions,
    listApiKeys,
    createApiKey,
    revokeApiKey,
    revokeSession,
    revokeOtherSessions,
    passkeysSupported,
    registerPasskey,
    signInWithPasskey,
    passkeyAutofillSupported,
    signInWithPasskeyAutofill,
    cancelPasskeyAutofill,
    startPasskeySignUp,
    completePasskeySignUp,
    listPasskeys,
    renamePasskey,
    deletePasskey,
    listOrganizations,
    listOrganizationRoles,
    listOrgDomains,
    addOrgDomain,
    verifyOrgDomainDns,
    sendOrgDomainEmail,
    verifyOrgDomainEmail,
    updateOrgDomain,
    removeOrgDomain,
    listOrgSuggestions,
    acceptOrgSuggestion,
    createOrganization,
    renameOrganization,
    setOrganizationTwoFactor,
    deleteOrganization,
    listOrgMembers,
    changeOrgRole,
    removeOrgMember,
    inviteToOrg,
    listOrgInvitations,
    revokeOrgInvitation,
    previewInvitation,
    acceptInvitation,
    setActiveOrganization,
  };
}

export type AuthClient = ReturnType<typeof createAuthClient>;
