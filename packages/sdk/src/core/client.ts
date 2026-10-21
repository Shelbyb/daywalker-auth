import { ACTIVE_COOKIE, SESSION_COOKIE, instanceIdFromKey, normalizeOrigin, type Config } from "./keys";

export type EmailAddress = { id: string; email: string; primary: boolean; verified: boolean };
export type User = {
  id: string;
  firstName: string | null;
  lastName: string | null;
  imageUrl: string | null;
  emailAddresses: EmailAddress[];
  publicMetadata: Record<string, unknown>;
  lastSignInAt: string | null;
  createdAt: string;
};
export type AuthState = {
  isLoaded: boolean;
  user: User | null;
  sessionId: string | null;
};

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
export function createAuthClient(config: Config & { /** Mirror the JWT into a cookie on your domain (default true) */ syncCookie?: boolean }) {
  instanceIdFromKey(config.publishableKey); // fail fast on a bad key
  const base = normalizeOrigin(config.frontendApi);
  const syncCookie = config.syncCookie ?? true;

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

  async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const res = await fetch(`${base}/v1/client/${path}`, {
      ...init,
      credentials: "include",
      headers: { "content-type": "application/json", "x-publishable-key": config.publishableKey },
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

  function clearLocal() {
    token = null;
    clearTimeout(timer);
    writeCookies(null);
    setState({ isLoaded: true, user: null, sessionId: null });
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
        if (e instanceof AuthError && e.status === 401) clearLocal();
        return null;
      })
      .finally(() => (inflight = null));
    return inflight;
  }

  async function load() {
    const r = await request<{ session: { id: string } | null; user: User | null }>("session", { method: "GET" }).catch(
      () => ({ session: null, user: null }),
    );
    if (!r.session) {
      clearLocal();
      return state;
    }
    setState({ isLoaded: true, user: r.user, sessionId: r.session.id });
    await getToken({ force: true });
    return state;
  }

  async function signIn(input: { email: string; password: string }) {
    const r = await request<{ user: User; sessionId: string; jwt: string }>("sign_in", { method: "POST", body: JSON.stringify(input) });
    acceptToken(r.jwt);
    setState({ isLoaded: true, user: r.user, sessionId: r.sessionId });
    channel?.postMessage("signed-in");
    return r.user;
  }

  async function signUp(input: { email: string; password: string; firstName?: string; lastName?: string }) {
    const r = await request<{ user: User; sessionId: string; jwt: string }>("sign_up", { method: "POST", body: JSON.stringify(input) });
    acceptToken(r.jwt);
    setState({ isLoaded: true, user: r.user, sessionId: r.sessionId });
    channel?.postMessage("signed-in");
    return r.user;
  }

  async function signOut() {
    await request("session", { method: "DELETE" }).catch(() => undefined);
    clearLocal();
    channel?.postMessage("signed-out"); // other tabs drop their in-memory token too
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
  async function requestPasswordReset(email: string) {
    await request("password/forgot", { method: "POST", body: JSON.stringify({ email }) });
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
  function signInWithOAuth(provider: "google" | "github", redirectUrl?: string) {
    const u = new URL(`${base}/v1/client/oauth/${provider}/start`);
    u.searchParams.set("pk", config.publishableKey);
    const back = redirectUrl ?? (typeof window !== "undefined" ? window.location.href : undefined);
    if (back) u.searchParams.set("redirect_url", back);
    window.location.assign(u.toString());
  }

  /** Public settings for this instance, e.g. which OAuth providers are enabled. */
  function getEnvironment() {
    return request<{ name: string; oauthProviders: ("google" | "github")[]; passwordMinLength: number }>("environment", { method: "GET" });
  }

  /** `fetch` that attaches `Authorization: Bearer <jwt>` for calls to your own backend. */
  async function authFetch(input: RequestInfo | URL, init: RequestInit = {}) {
    const jwt = await getToken();
    const headers = new Headers(init.headers);
    if (jwt) headers.set("authorization", `Bearer ${jwt}`);
    return fetch(input, { ...init, headers });
  }

  /** URL of the hosted sign-in / sign-up page that returns to `redirectUrl` afterwards. */
  function hostedUrl(page: "sign-in" | "sign-up" | "forgot-password", redirectUrl?: string) {
    const u = new URL(`${base}/${page}`);
    u.searchParams.set("pk", config.publishableKey);
    if (redirectUrl) u.searchParams.set("redirect_url", redirectUrl);
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
    signUp,
    signOut,
    authFetch,
    hostedUrl,
    sendVerificationCode,
    verifyEmail,
    requestPasswordReset,
    resetPassword,
    signInWithOAuth,
    getEnvironment,
  };
}

export type AuthClient = ReturnType<typeof createAuthClient>;
