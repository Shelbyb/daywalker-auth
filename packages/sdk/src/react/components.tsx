"use client";

/**
 * Drop-in auth components: <SignIn />, <SignUp />, <UserButton />, <OrganizationSwitcher />.
 *
 * - No inline styles and no injected HTML, so they work under a strict Content Security Policy.
 * - Every element has a stable `dw-*` class. Import "@daywalker/auth/styles.css" for a ready-made
 *   look, write your own CSS against those classes, or pass `appearance.classNames` to add yours.
 * - They read the instance's settings (enabled providers, email codes, terms) and adapt.
 */
import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from "react";
import { AuthError, type ReverificationNeed, type ReverificationOptions, type OAuthProvider, type OrgInfo, type OrgRoleInfo, type OrgDomainInfo, type OrgMember, type OrgInvitation, type OrgSuggestion, type OrganizationSettings, type SessionInfo, type User } from "../core/client";
import { staleFactors } from "../core/fresh";
import { useAuthClient, useAuthUrls, useUser } from "./index";

/** `?redirect_url=` from the current page if it is same-origin, else the configured fallback (Clerk-style). */
function useAfterAuthUrl(explicit: string | undefined, fallback: string | undefined) {
  const [url, setUrl] = useState(explicit ?? fallback);
  useEffect(() => {
    if (explicit) return setUrl(explicit);
    const q = new URLSearchParams(window.location.search).get("redirect_url");
    try { if (q && new URL(q, window.location.href).origin === window.location.origin) return setUrl(q); } catch { /* ignore */ }
    setUrl(fallback);
  }, [explicit, fallback]);
  return url;
}

/** Carries the current `redirect_url` over to the other page (sign-in ↔ sign-up). */
function withRedirect(href: string | undefined) {
  if (!href || typeof window === "undefined") return href;
  const q = new URLSearchParams(window.location.search).get("redirect_url");
  if (!q) return href;
  const u = new URL(href, window.location.href);
  u.searchParams.set("redirect_url", q);
  return u.origin === window.location.origin ? u.pathname + u.search : u.href;
}

export type Appearance = {
  /** Extra classes per part, e.g. { button: "btn btn-primary", input: "form-control" }. */
  classNames?: Partial<Record<Part, string>>;
};
type Part =
  | "root" | "header" | "title" | "subtitle" | "form" | "field" | "label" | "input" | "button" | "buttonSecondary"
  | "providers" | "divider" | "error" | "info" | "footer" | "link" | "checkbox"
  | "userButton" | "avatar" | "menu" | "menuItem" | "orgSwitcher" | "tabs" | "tab" | "list" | "listItem" | "select" | "modalBackdrop";

const cx = (appearance: Appearance | undefined, part: Part, base: string) => [base, appearance?.classNames?.[part]].filter(Boolean).join(" ");

export type EnvironmentInfo = {
  name: string;
  /** "development" instances show a banner in the sign-in and sign-up components. */
  instanceEnvironment?: "development" | "production";
  /** Development only: test addresses (+daywalker_test) accept the fixed code 424242. */
  testMode?: boolean;
  oauthProviders: OAuthProvider[];
  oauthProviderLabels: Partial<Record<OAuthProvider, string>>;
  passwordMinLength: number;
  emailCodeSignIn: boolean;
  passkeySignUp?: boolean;
  ssoEnabled?: boolean;
  /** Organization rules set by the app in the dashboard. */
  organizations?: OrganizationSettings;
  legal: { required: boolean; termsUrl: string | null; privacyUrl: string | null };
  /** Cloudflare Turnstile, when the app has the human check on. */
  captcha?: { provider: "turnstile"; siteKey: string } | null;
};

// ---------- Human check (Cloudflare Turnstile) ----------

type TurnstileApi = { render: (el: HTMLElement, o: Record<string, unknown>) => string; remove: (id: string) => void };
let turnstileLoad: Promise<TurnstileApi> | null = null;
function loadTurnstile() {
  return (turnstileLoad ??= new Promise((resolve, reject) => {
    const w = window as unknown as { turnstile?: TurnstileApi };
    if (w.turnstile) return resolve(w.turnstile);
    const el = document.createElement("script");
    el.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    el.async = true;
    el.onload = () => (w.turnstile ? resolve(w.turnstile) : reject(new Error("turnstile")));
    el.onerror = () => {
      turnstileLoad = null;
      reject(new Error("turnstile"));
    };
    document.head.appendChild(el);
  }));
}

/**
 * Renders the widget; `onToken` gets each answer (or null when it expires). Change `round` to get a
 * fresh one (answers work once). `action` names the form; the server checks it.
 */
export function Captcha({ siteKey, action, onToken, round }: { siteKey: string; action: "signup" | "login" | "email_code" | "password_reset"; onToken: (t: string | null) => void; round: number }) {
  const ref = useRef<HTMLDivElement>(null);
  const cb = useRef(onToken);
  cb.current = onToken;
  useEffect(() => {
    let id: string | null = null, api: TurnstileApi | null = null, live = true;
    cb.current(null);
    loadTurnstile()
      .then((t) => {
        if (!live || !ref.current) return;
        api = t;
        id = t.render(ref.current, { sitekey: siteKey, action, callback: (tok: string) => cb.current(tok), "expired-callback": () => cb.current(null), "error-callback": () => cb.current(null) });
      })
      .catch(() => undefined);
    return () => {
      live = false;
      if (api && id) api.remove(id);
    };
  }, [siteKey, action, round]);
  return <div ref={ref} className="dw-captcha" />;
}

function useEnvironment(initial?: EnvironmentInfo) {
  const c = useAuthClient();
  const [env, setEnv] = useState<EnvironmentInfo | null>(initial ?? null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    if (initial) return; // already known (the hosted pages pass it in)
    let live = true;
    c.getEnvironment()
      .then((e) => live && setEnv(e))
      .catch(() => live && setFailed(true));
    return () => {
      live = false;
    };
  }, [c]);
  return { env, failed };
}

// Fixed messages for the codes the OAuth/SSO redirects put in the URL: nothing from the URL is ever shown as-is.
const REDIRECT_ERRORS: Record<string, string> = {
  oauth_cancelled: "Sign-in was cancelled.",
  oauth_failed: "We couldn't sign you in with that provider. Please try again.",
  email_unverified: "That account has no verified email address. Verify it with the provider, or sign in with email.",
  provider_disabled: "That sign-in option isn't available for this app.",
  forbidden: "This account is suspended.",
  sso_required: "Your company requires single sign-on. Use “Sign in with SSO” instead.",
  sso_not_configured: "Single sign-on isn't set up for that email domain.",
  legal_required: "Please accept the terms to create an account.",
};
const redirectError = (code?: string) => (code ? (REDIRECT_ERRORS[code] ?? null) : null);

/** Errors that mean the app refused this person (not a mistake they can fix here). Mirrors the service's reason codes. */
function refusalReason(e: unknown): string | null {
  if (!(e instanceof AuthError)) return null;
  if (e.code === "sign_up_not_allowed") return "sign_up_restricted";
  if (e.code === "forbidden" && /suspended/i.test(e.message)) return "account_locked";
  if (e.code === "forbidden" && /origin not allowed/i.test(e.message)) return "origin_not_allowed";
  return null;
}
/** Sends the browser to the "Unauthorized sign in" page for a refusal. Returns false when it didn't. */
function goUnauthorized(unauthorizedUrl: string | undefined, e: unknown) {
  const reason = refusalReason(e);
  if (!unauthorizedUrl || !reason) return false;
  const to = new URL(unauthorizedUrl, window.location.href);
  to.searchParams.set("reason", reason);
  window.location.assign(to.toString());
  return true;
}

const message = (e: unknown) => (e instanceof AuthError ? e.message : "Network error. Check your connection and try again.");
const displayName = (u: User) => [u.firstName, u.lastName].filter(Boolean).join(" ") || u.emailAddresses[0]?.email || "";

/** Calls onDone, or navigates to `redirectUrl`. Only same-origin paths or absolute URLs given by the developer. */
function finish(redirectUrl: string | undefined, onDone: ((u: User) => void) | undefined, user: User) {
  if (onDone) onDone(user);
  else if (redirectUrl) window.location.assign(redirectUrl);
}

type CommonProps = {
  /** Settings already fetched on the server, to skip the request (and the loading flash). */
  initialEnvironment?: EnvironmentInfo;
  /** An error code from a redirect back (?error=...). Shown as a fixed message; unknown codes are ignored. */
  initialError?: string;
  /** Show the "signed in" state straight away, e.g. after returning from a provider. */
  signedIn?: boolean;
  /** Where to go after signing in. Ignored when `onSignedIn` is given. */
  redirectUrl?: string;
  onSignedIn?: (user: User) => void;
  appearance?: Appearance;
  /** When set, refusals by the app (suspended account, restricted sign-ups, origin not allowed) go to this page with `?reason=` instead of showing inline. */
  unauthorizedUrl?: string;
};

// ---------- Small building blocks ----------

function Field(props: { a?: Appearance; /** Placed on the input as-is, e.g. "username webauthn" for passkey autofill. */ label: string; name: string; type?: string; autoComplete?: string; required?: boolean; value?: string; onChange?: (v: string) => void; inputMode?: "numeric"; maxLength?: number; autoFocus?: boolean }) {
  const id = useId();
  return (
    <div className={cx(props.a, "field", "dw-field")}>
      <label htmlFor={id} className={cx(props.a, "label", "dw-label")}>{props.label}</label>
      <input
        id={id}
        name={props.name}
        type={props.type ?? "text"}
        autoComplete={props.autoComplete}
        required={props.required}
        inputMode={props.inputMode}
        maxLength={props.maxLength ?? 254}
        autoFocus={props.autoFocus}
        {...(props.onChange ? { value: props.value ?? "", onChange: (e) => props.onChange!(e.target.value) } : {})}
        className={cx(props.a, "input", "dw-input")}
      />
    </div>
  );
}

function Alert({ a, tone = "error", children }: { a?: Appearance; tone?: "error" | "info"; children: ReactNode }) {
  return (
    <p role={tone === "error" ? "alert" : "status"} className={cx(a, tone === "error" ? "error" : "info", tone === "error" ? "dw-error" : "dw-info")}>
      {children}
    </p>
  );
}

/** Shown on development instances so nobody mistakes them for the real thing. Not removable through `appearance`. */
function DevBanner({ env }: { env?: EnvironmentInfo | null }) {
  if (env?.instanceEnvironment !== "development") return null;
  return <p role="note" className="dw-dev-banner">{env.testMode ? "Development mode, test mode on: +daywalker_test emails use code 424242" : "Development mode: for testing, not real users"}</p>;
}

function Shell({ a, title, subtitle, children, footer, env }: { a?: Appearance; title: string; subtitle?: string; children: ReactNode; footer?: ReactNode; env?: EnvironmentInfo | null }) {
  return (
    <div className={cx(a, "root", "dw-root")}>
      <DevBanner env={env} />
      <div className={cx(a, "header", "dw-header")}>
        <h2 className={cx(a, "title", "dw-title")}>{title}</h2>
        {subtitle && <p className={cx(a, "subtitle", "dw-subtitle")}>{subtitle}</p>}
      </div>
      {children}
      {footer && <div className={cx(a, "footer", "dw-footer")}>{footer}</div>}
    </div>
  );
}

function Providers({ a, env, redirectUrl, legalAccepted, disabled }: { a?: Appearance; env: EnvironmentInfo; redirectUrl?: string; legalAccepted?: boolean; disabled?: boolean }) {
  const c = useAuthClient();
  if (!env.oauthProviders.length) return null;
  return (
    <div className={cx(a, "providers", "dw-providers")}>
      {env.oauthProviders.map((p) => (
        <button
          key={p}
          type="button"
          disabled={disabled}
          className={cx(a, "buttonSecondary", `dw-button dw-button-secondary dw-provider dw-provider-${p}`)}
          onClick={() => c.signInWithOAuth(p, redirectUrl ?? window.location.href, { legalAccepted })}
        >
          Continue with {env.oauthProviderLabels[p] ?? p}
        </button>
      ))}
    </div>
  );
}

const Divider = ({ a }: { a?: Appearance }) => <div className={cx(a, "divider", "dw-divider")}><span>or</span></div>;

function SecondFactor({ a, onUser }: { a?: Appearance; onUser: (u: User) => void }) {
  const c = useAuthClient();
  const [backup, setBackup] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sms, setSms] = useState<string | null>(null);
  const [texted, setTexted] = useState(false);
  const [key, setKey] = useState(false);
  useEffect(() => {
    c.getSecondFactorOptions().then((o) => { setSms(o.sms); setKey(o.securityKey); }).catch(() => {});
  }, [c]);
  async function useSecurityKey() {
    setBusy(true);
    setError(null);
    try {
      onUser((await c.completeSecondFactorWithSecurityKey()).user);
    } catch (err) {
      if (!(err instanceof AuthError && err.code === "security_key_cancelled")) setError(message(err));
    } finally {
      setBusy(false);
    }
  }
  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onUser((await c.completeSecondFactor(String(new FormData(e.currentTarget).get("code") ?? ""), !backup && texted ? "sms" : undefined)).user);
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <form onSubmit={submit} className={cx(a, "form", "dw-form")} noValidate>
      <p className={cx(a, "subtitle", "dw-subtitle")}>{backup ? "Enter one of your backup codes." : texted ? `Enter the code we texted to ${sms}.` : "Enter the 6-digit code from your authenticator app."}</p>
      <Field a={a} key={backup ? "b" : "t"} label={backup ? "Backup code" : "Authentication code"} name="code" autoComplete="one-time-code" inputMode={backup ? undefined : "numeric"} maxLength={backup ? 11 : 6} required autoFocus />
      {error && <Alert a={a}>{error}</Alert>}
      <button disabled={busy} className={cx(a, "button", "dw-button dw-button-primary")}>{busy ? "Please wait…" : "Verify"}</button>
      {key && !backup && (
        <button type="button" disabled={busy} className={cx(a, "buttonSecondary", "dw-button dw-button-secondary dw-security-key")} onClick={() => void useSecurityKey()}>
          Use a security key
        </button>
      )}
      {sms && !backup && (
        <button type="button" className={cx(a, "link", "dw-link")} onClick={() => c.sendSecondFactorSms().then(() => setTexted(true)).catch((e) => setError(message(e)))}>
          {texted ? "Send another code" : `Text a code to ${sms}`}
        </button>
      )}
      <button type="button" className={cx(a, "link", "dw-link")} onClick={() => setBackup((b) => !b)}>
        {backup ? "Use your authenticator app" : "Use a backup code"}
      </button>
    </form>
  );
}

function SetupTwoFactor({ a, redirectUrl }: { a?: Appearance; redirectUrl?: string }) {
  const c = useAuthClient();
  return (
    <Shell a={a} title="Set up two-step verification" subtitle="This app requires it before you can continue.">
      <a href={c.hostedUrl("account", redirectUrl ?? window.location.href)} className={cx(a, "button", "dw-button dw-button-primary")}>Set it up now</a>
    </Shell>
  );
}

// ---------- <SignIn /> ----------

export function SignIn({ redirectUrl: explicitRedirect, onSignedIn, appearance: a, signUpUrl: explicitSignUp, initialEnvironment, initialError, signedIn, unauthorizedUrl }: CommonProps & { /** Link for "No account yet?". Defaults to `signUpUrl` on `<AuthProvider>`. */ signUpUrl?: string }) {
  const urls = useAuthUrls();
  const redirectUrl = useAfterAuthUrl(explicitRedirect, urls.signInFallbackRedirectUrl);
  const signUpUrl = withRedirect(explicitSignUp ?? urls.signUpUrl);
  const c = useAuthClient();
  const { env, failed } = useEnvironment(initialEnvironment);
  const [step, setStep] = useState<"password" | "email-code" | "code-sent" | "second-factor" | "setup" | "done">(signedIn ? "done" : "password");
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [captchaRound, setCaptchaRound] = useState(0);
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(redirectError(initialError));
  const [info, setInfo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [doneUser, setDoneUser] = useState<User | null>(null);
  const [passkeys, setPasskeys] = useState(false); // only known in the browser
  useEffect(() => setPasskeys(c.passkeysSupported()), [c]);

  // Conditional UI: saved passkeys show up in the email field's autofill list. Re-armed every four minutes
  // (a challenge lasts five), and whenever another passkey prompt has stopped it.
  const [autofill, setAutofill] = useState(false);
  const busyRef = useRef(false);
  const autofillOn = step === "password" && passkeys && autofill;
  useEffect(() => {
    let alive = true;
    c.passkeyAutofillSupported().then((ok) => alive && setAutofill(ok));
    return () => { alive = false; };
  }, [c]);
  useEffect(() => {
    if (!autofillOn) return;
    let alive = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const arm = async () => {
      while (alive) {
        timer = setTimeout(() => c.cancelPasskeyAutofill(), 240_000);
        try {
          const r = await c.signInWithPasskeyAutofill();
          if (!alive) return;
          if (r.status === "needs_second_factor") setStep("second-factor");
          else done(r.user);
          return;
        } catch (err) {
          if (!alive) return;
          if (!(err instanceof AuthError && err.code === "passkey_cancelled")) {
            if (goUnauthorized(unauthorizedUrl, err)) return;
            setError(message(err)); // a real failure (e.g. a revoked passkey): show it and stop retrying
            return;
          }
          // Cancelled by the timer or by another passkey prompt: wait for that prompt to finish, then arm again.
          do await new Promise((r) => setTimeout(r, 400)); while (alive && busyRef.current);
        } finally {
          if (timer) clearTimeout(timer);
        }
      }
    };
    void arm();
    return () => { alive = false; if (timer) clearTimeout(timer); c.cancelPasskeyAutofill(); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [autofillOn, c]);

  const done = (u: User) => {
    setDoneUser(u);
    if (c.state.twoFactorSetupRequired) return setStep("setup"); // the app requires two-step verification first
    setStep("done");
    finish(redirectUrl, onSignedIn, u);
  };
  async function run(fn: () => Promise<void>) {
    busyRef.current = true;
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      if (goUnauthorized(unauthorizedUrl, err)) return;
      if (!(err instanceof AuthError && err.code === "passkey_cancelled")) setError(message(err));
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }

  if (failed) return <Shell a={a} title="Sign in"><Alert a={a}>Sign-in isn&apos;t available right now. Please try again later.</Alert></Shell>;
  if (!env) return <div className={cx(a, "root", "dw-root dw-loading")} aria-busy="true" />;
  if (step === "done") return <Shell a={a} title="You're signed in" subtitle={doneUser ? `Welcome, ${displayName(doneUser)}.` : undefined}><span /></Shell>;
  if (step === "second-factor") return <Shell a={a} title="Two-step verification"><SecondFactor a={a} onUser={done} /></Shell>;
  if (step === "setup") return <SetupTwoFactor a={a} redirectUrl={redirectUrl} />;

  const footer = signUpUrl ? <>No account yet? <a href={signUpUrl} className={cx(a, "link", "dw-link")}>Sign up</a></> : undefined;

  if (step === "email-code" || step === "code-sent")
    return (
      <Shell a={a} title={step === "code-sent" ? "Check your email" : "Sign in with an email code"} subtitle={env.name}>
        {step === "email-code" ? (
          <form className={cx(a, "form", "dw-form")} onSubmit={(e) => { e.preventDefault(); void run(async () => { try { await c.sendSignInCode({ email, redirectUrl, captchaToken: captchaToken ?? undefined }); } finally { setCaptchaRound((n) => n + 1); } setInfo(`If ${email} has an account, we've sent it a code and a sign-in link.`); setStep("code-sent"); }); }}>
            <Field a={a} label="Email" name="email" type="email" autoComplete="email" required value={email} onChange={setEmail} autoFocus />
            {env.captcha && <Captcha siteKey={env.captcha.siteKey} action="email_code" onToken={setCaptchaToken} round={captchaRound} />}
            {error && <Alert a={a}>{error}</Alert>}
            <button disabled={busy || (!!env.captcha && !captchaToken)} className={cx(a, "button", "dw-button dw-button-primary")}>{busy ? "Please wait…" : "Email me a code"}</button>
            <button type="button" className={cx(a, "link", "dw-link")} onClick={() => { setStep("password"); setError(null); }}>Use a password instead</button>
          </form>
        ) : (
          <form className={cx(a, "form", "dw-form")} onSubmit={(e) => { e.preventDefault(); const code = String(new FormData(e.currentTarget).get("code") ?? ""); void run(async () => { const r = await c.signInWithEmailCode({ email, code }); if (r.status === "needs_second_factor") setStep("second-factor"); else done(r.user); }); }}>
            {info && <Alert a={a} tone="info">{info}</Alert>}
            <Field a={a} label="Code" name="code" autoComplete="one-time-code" inputMode="numeric" maxLength={6} required autoFocus />
            {error && <Alert a={a}>{error}</Alert>}
            <button disabled={busy} className={cx(a, "button", "dw-button dw-button-primary")}>{busy ? "Please wait…" : "Sign in"}</button>
            <button type="button" className={cx(a, "link", "dw-link")} onClick={() => { setStep("email-code"); setError(null); }}>Use a different email</button>
          </form>
        )}
      </Shell>
    );

  return (
    <Shell a={a} env={env} title="Sign in" subtitle={`to continue to ${env.name}`} footer={footer}>
      {(env.oauthProviders.length > 0 || passkeys) && (
        <>
          <div className={cx(a, "providers", "dw-providers")}>
            {passkeys && (
              <button type="button" disabled={busy} className={cx(a, "buttonSecondary", "dw-button dw-button-secondary dw-passkey")}
                onClick={() => void run(async () => { const r = await c.signInWithPasskey(); if (r.status !== "needs_second_factor") done(r.user); })}>
                Sign in with a passkey
              </button>
            )}
          </div>
          <Providers a={a} env={env} redirectUrl={redirectUrl} />
          <Divider a={a} />
        </>
      )}
      <form className={cx(a, "form", "dw-form")} noValidate onSubmit={(e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        void run(async () => {
          let r;
          try {
            r = await c.signIn({ email: String(f.get("email") ?? ""), password: String(f.get("password") ?? ""), captchaToken: captchaToken ?? undefined });
          } finally {
            setCaptchaRound((n) => n + 1); // each answer works once
          }
          if (r.status === "needs_second_factor") setStep("second-factor");
          else done(r.user);
        });
      }}>
        <Field a={a} label="Email" name="email" type="email" autoComplete={autofill ? "username webauthn" : "email"} required value={email} onChange={setEmail} />
        <Field a={a} label="Password" name="password" type="password" autoComplete="current-password" required maxLength={256} />
        <a href={c.hostedUrl("forgot-password", redirectUrl ?? window.location.href)} className={cx(a, "link", "dw-link dw-forgot")}>Forgot password?</a>
        {env.captcha && <Captcha siteKey={env.captcha.siteKey} action="login" onToken={setCaptchaToken} round={captchaRound} />}
        {error && <Alert a={a}>{error}</Alert>}
        <button disabled={busy || (!!env.captcha && !captchaToken)} className={cx(a, "button", "dw-button dw-button-primary")}>{busy ? "Please wait…" : "Continue"}</button>
        {env.ssoEnabled && (
          <button type="button" disabled={busy} className={cx(a, "buttonSecondary", "dw-button dw-button-secondary dw-sso")} onClick={() => void run(async () => {
            if (!/^[^@\s]+@[^@\s]+$/.test(email.trim())) throw new AuthError(400, "email_required", "Enter your work email first");
            const r = await c.checkSSO(email.trim());
            if (!r.sso) throw new AuthError(400, "sso_not_configured", "Single sign-on isn't set up for that email domain");
            c.signInWithSSO(email.trim(), redirectUrl);
          })}>
            Sign in with SSO
          </button>
        )}
        {env.emailCodeSignIn && (
          <button type="button" className={cx(a, "buttonSecondary", "dw-button dw-button-secondary dw-email-code")} onClick={() => { setStep("email-code"); setError(null); }}>
            Email me a sign-in code instead
          </button>
        )}
      </form>
    </Shell>
  );
}

// ---------- <SignUp /> ----------

export function SignUp({ redirectUrl: explicitRedirect, onSignedIn, appearance: a, signInUrl: explicitSignIn, initialEnvironment, initialError, signedIn, unauthorizedUrl }: CommonProps & { /** Link for "Already have an account?". Defaults to `signInUrl` on `<AuthProvider>`. */ signInUrl?: string }) {
  const urls = useAuthUrls();
  const redirectUrl = useAfterAuthUrl(explicitRedirect, urls.signUpFallbackRedirectUrl);
  const signInUrl = withRedirect(explicitSignIn ?? urls.signInUrl);
  const c = useAuthClient();
  const { env, failed } = useEnvironment(initialEnvironment);
  const [step, setStep] = useState<"form" | "passkey" | "passkey-code" | "verify" | "setup" | "done">(signedIn ? "done" : "form");
  const [pkProfile, setPkProfile] = useState<{ email: string; firstName?: string; lastName?: string } | null>(null);
  const [passkeys, setPasskeys] = useState(false); // only known in the browser
  useEffect(() => setPasskeys(c.passkeysSupported()), [c]);
  const [captchaToken, setCaptchaToken] = useState<string | null>(null);
  const [captchaRound, setCaptchaRound] = useState(0);
  const [accepted, setAccepted] = useState(false);
  const [error, setError] = useState<string | null>(redirectError(initialError));
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [user, setUser] = useState<User | null>(null);
  const sent = useRef(false);

  useEffect(() => {
    if (step !== "verify" || sent.current) return;
    sent.current = true;
    c.sendVerificationCode().catch((e) => setError(message(e)));
  }, [step, c]);

  if (failed) return <Shell a={a} title="Create your account"><Alert a={a}>Sign-up isn&apos;t available right now. Please try again later.</Alert></Shell>;
  if (!env) return <div className={cx(a, "root", "dw-root dw-loading")} aria-busy="true" />;
  const needsConsent = env.legal.required && !!env.legal.termsUrl;
  const complete = (u: User) => {
    setUser(u);
    if (c.state.twoFactorSetupRequired) return setStep("setup"); // the app requires two-step verification first
    setStep("done");
    finish(redirectUrl, onSignedIn, u);
  };

  if (step === "setup") return <SetupTwoFactor a={a} redirectUrl={redirectUrl} />;
  if (step === "done") return <Shell a={a} title="You're all set" subtitle={user ? `Welcome, ${displayName(user)}.` : undefined}><span /></Shell>;
  if (step === "passkey" || step === "passkey-code") {
    const back = <button type="button" className={cx(a, "link", "dw-link")} onClick={() => { setStep("form"); setError(null); }}>Use a password instead</button>;
    if (step === "passkey-code" && pkProfile)
      return (
        <Shell a={a} title="Check your email" subtitle={`We sent a 6-digit code to ${pkProfile.email}. Then you'll create your passkey.`}>
          <form className={cx(a, "form", "dw-form")} onSubmit={async (e) => {
            e.preventDefault();
            const code = String(new FormData(e.currentTarget).get("code") ?? "");
            setBusy(true);
            setError(null);
            try {
              const r = await c.completePasskeySignUp({ email: pkProfile.email, code });
              complete(r.user);
            } catch (err) {
              if (goUnauthorized(unauthorizedUrl, err)) return;
              if (!(err instanceof AuthError && err.code === "passkey_cancelled")) setError(message(err));
              else setError("Passkey setup was cancelled. Press the button to try again; your code is used up, so you may need a new one.");
            } finally {
              setBusy(false);
            }
          }}>
            <Field a={a} label="Code" name="code" autoComplete="one-time-code" inputMode="numeric" maxLength={6} required autoFocus />
            {error && <Alert a={a}>{error}</Alert>}
            <button disabled={busy} className={cx(a, "button", "dw-button dw-button-primary")}>{busy ? "Please wait…" : "Verify and create passkey"}</button>
            <button type="button" className={cx(a, "link", "dw-link")} onClick={() => { setStep("passkey"); setError(null); }}>Use a different email, or send a new code</button>
          </form>
        </Shell>
      );
    return (
      <Shell a={a} title="Sign up with a passkey" subtitle={`to continue to ${env.name}`}>
        {needsConsent && (
          <label className={cx(a, "checkbox", "dw-checkbox")}>
            <input type="checkbox" checked={accepted} onChange={(e) => setAccepted(e.target.checked)} />
            <span>
              I agree to the <a href={env.legal.termsUrl!} target="_blank" rel="noopener noreferrer" className={cx(a, "link", "dw-link")}>Terms of Service</a>
              {env.legal.privacyUrl && <> and <a href={env.legal.privacyUrl} target="_blank" rel="noopener noreferrer" className={cx(a, "link", "dw-link")}>Privacy Policy</a></>}
            </span>
          </label>
        )}
        <form className={cx(a, "form", "dw-form")} noValidate onSubmit={async (e) => {
          e.preventDefault();
          const f = new FormData(e.currentTarget);
          const profile = { email: String(f.get("email") ?? "").trim().toLowerCase(), firstName: String(f.get("firstName") ?? "") || undefined, lastName: String(f.get("lastName") ?? "") || undefined };
          setBusy(true);
          setError(null);
          try {
            await c.startPasskeySignUp({ ...profile, legalAccepted: needsConsent ? accepted : undefined, captchaToken: captchaToken ?? undefined });
            setPkProfile(profile);
            setStep("passkey-code");
          } catch (err) {
            if (goUnauthorized(unauthorizedUrl, err)) return;
            setError(message(err));
          } finally {
            setCaptchaRound((n) => n + 1); // each answer works once
            setBusy(false);
          }
        }}>
          <div className="dw-row">
            <Field a={a} label="First name" name="firstName" autoComplete="given-name" maxLength={100} />
            <Field a={a} label="Last name" name="lastName" autoComplete="family-name" maxLength={100} />
          </div>
          <Field a={a} label="Email" name="email" type="email" autoComplete="email" required autoFocus />
          {env.captcha && <Captcha siteKey={env.captcha.siteKey} action="signup" onToken={setCaptchaToken} round={captchaRound} />}
          {error && <Alert a={a}>{error}</Alert>}
          <button disabled={busy || (needsConsent && !accepted) || (!!env.captcha && !captchaToken)} className={cx(a, "button", "dw-button dw-button-primary")}>{busy ? "Please wait…" : "Email me a code"}</button>
          {back}
        </form>
      </Shell>
    );
  }
  if (step === "verify")
    return (
      <Shell a={a} title="Verify your email" subtitle={`We sent a 6-digit code to ${user?.emailAddresses[0]?.email ?? "your email"}.`}>
        <form className={cx(a, "form", "dw-form")} onSubmit={async (e) => {
          e.preventDefault();
          const code = String(new FormData(e.currentTarget).get("code") ?? "");
          setBusy(true);
          setError(null);
          try {
            complete(await c.verifyEmail(code));
          } catch (err) {
            setError(message(err));
          } finally {
            setBusy(false);
          }
        }}>
          <Field a={a} label="Code" name="code" autoComplete="one-time-code" inputMode="numeric" maxLength={6} required autoFocus />
          {error && <Alert a={a}>{error}</Alert>}
          <button disabled={busy} className={cx(a, "button", "dw-button dw-button-primary")}>{busy ? "Please wait…" : "Verify"}</button>
          <button type="button" className={cx(a, "link", "dw-link")} onClick={() => c.sendVerificationCode().then(() => setError(null)).catch((e) => setError(message(e)))}>Send a new code</button>
        </form>
      </Shell>
    );

  const footer = signInUrl ? <>Already have an account? <a href={signInUrl} className={cx(a, "link", "dw-link")}>Sign in</a></> : undefined;
  return (
    <Shell a={a} env={env} title="Create your account" subtitle={`to continue to ${env.name}`} footer={footer}>
      {needsConsent && (
        <label className={cx(a, "checkbox", "dw-checkbox")}>
          <input type="checkbox" checked={accepted} onChange={(e) => setAccepted(e.target.checked)} />
          <span>
            I agree to the <a href={env.legal.termsUrl!} target="_blank" rel="noopener noreferrer" className={cx(a, "link", "dw-link")}>Terms of Service</a>
            {env.legal.privacyUrl && <> and <a href={env.legal.privacyUrl} target="_blank" rel="noopener noreferrer" className={cx(a, "link", "dw-link")}>Privacy Policy</a></>}
          </span>
        </label>
      )}
      {env.oauthProviders.length > 0 && (
        <>
          <Providers a={a} env={env} redirectUrl={redirectUrl} legalAccepted={accepted} disabled={needsConsent && !accepted} />
          <Divider a={a} />
        </>
      )}
      <form className={cx(a, "form", "dw-form")} noValidate onSubmit={async (e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        setBusy(true);
        setError(null);
        setFieldErrors({});
        try {
          const u = await c.signUp({
            email: String(f.get("email") ?? ""),
            password: String(f.get("password") ?? ""),
            firstName: String(f.get("firstName") ?? "") || undefined,
            lastName: String(f.get("lastName") ?? "") || undefined,
            legalAccepted: needsConsent ? accepted : undefined,
            captchaToken: captchaToken ?? undefined,
          });
          setUser(u);
          if (u.emailAddresses[0]?.verified) complete(u);
          else setStep("verify");
        } catch (err) {
          if (goUnauthorized(unauthorizedUrl, err)) return;
          setError(message(err));
          if (err instanceof AuthError) setFieldErrors(Object.fromEntries(err.fields.map((x) => [x.path, x.message])));
          setCaptchaRound((n) => n + 1); // each answer works once
        } finally {
          setBusy(false);
        }
      }}>
        <div className="dw-row">
          <Field a={a} label="First name" name="firstName" autoComplete="given-name" maxLength={100} />
          <Field a={a} label="Last name" name="lastName" autoComplete="family-name" maxLength={100} />
        </div>
        <Field a={a} label="Email" name="email" type="email" autoComplete="email" required />
        <Field a={a} label={`Password (at least ${env.passwordMinLength} characters)`} name="password" type="password" autoComplete="new-password" required maxLength={256} />
        {env.captcha && <Captcha siteKey={env.captcha.siteKey} action="signup" onToken={setCaptchaToken} round={captchaRound} />}
        {Object.values(fieldErrors)[0] && <Alert a={a}>{Object.values(fieldErrors)[0]}</Alert>}
        {error && !Object.keys(fieldErrors).length && <Alert a={a}>{error}</Alert>}
        <button disabled={busy || (needsConsent && !accepted) || (!!env.captcha && !captchaToken)} className={cx(a, "button", "dw-button dw-button-primary")}>{busy ? "Please wait…" : "Create account"}</button>
        {env.passkeySignUp && passkeys && (
          <button type="button" disabled={busy} className={cx(a, "buttonSecondary", "dw-button dw-button-secondary dw-passkey")} onClick={() => { setStep("passkey"); setError(null); }}>
            Sign up with a passkey instead
          </button>
        )}
      </form>
    </Shell>
  );
}

// ---------- <UserButton /> ----------

function useDismiss(open: boolean, close: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && close();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && close();
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, close]);
  return ref;
}

/** Avatar with a menu: the user's name, "Manage account" and "Sign out". */
export function UserButton({ afterSignOutUrl, appearance: a, className }: { afterSignOutUrl?: string; appearance?: Appearance; className?: string }) {
  const { user } = useUser();
  const c = useAuthClient();
  const [open, setOpen] = useState(false);
  const ref = useDismiss(open, () => setOpen(false));
  if (!user) return null;
  const email = user.emailAddresses.find((e) => e.primary)?.email ?? user.emailAddresses[0]?.email ?? "";
  const name = displayName(user) || email;
  const initials = ((user.firstName?.[0] ?? email[0] ?? "?") + (user.lastName?.[0] ?? "")).toUpperCase();
  return (
    <div ref={ref} className={[cx(a, "userButton", "dw-user-button"), className].filter(Boolean).join(" ")}>
      <button type="button" aria-haspopup="menu" aria-expanded={open} aria-label={`Account: ${name}`} className={cx(a, "avatar", "dw-avatar")} onClick={() => setOpen((o) => !o)}>
        {initials}
      </button>
      {open && (
        <div role="menu" className={cx(a, "menu", "dw-menu")}>
          <div className="dw-menu-name">{name}</div>
          {name !== email && <div className="dw-menu-email">{email}</div>}
          <a role="menuitem" className={cx(a, "menuItem", "dw-menu-item")} href={c.hostedUrl("account", window.location.href)}>Manage account</a>
          <button role="menuitem" type="button" className={cx(a, "menuItem", "dw-menu-item")} onClick={async () => {
            const { redirecting } = await c.signOut({ redirectUrl: afterSignOutUrl });
            setOpen(false);
            if (afterSignOutUrl && !redirecting) window.location.assign(afterSignOutUrl);
          }}>
            Sign out
          </button>
        </div>
      )}
    </div>
  );
}

// ---------- <OrganizationSwitcher /> ----------

/** Reads the active org from the current session token (display only; your server verifies the token). */
async function activeOrgId(getToken: () => Promise<string | null>) {
  const jwt = await getToken();
  if (!jwt) return null;
  try {
    const b64 = jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return (JSON.parse(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4))) as { org_id?: string }).org_id ?? null;
  } catch {
    return null;
  }
}

/** Switch between personal and organization accounts, or create an organization. */
export function OrganizationSwitcher({ appearance: a, hidePersonal = false, onChange }: { appearance?: Appearance; hidePersonal?: boolean; onChange?: (org: OrgInfo | null) => void }) {
  const c = useAuthClient();
  const { user } = useUser();
  const [orgs, setOrgs] = useState<OrgInfo[] | null>(null);
  const [active, setActive] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [rules, setRules] = useState<OrganizationSettings | null>(null);
  const [suggestions, setSuggestions] = useState<OrgSuggestion[]>([]);
  const ref = useDismiss(open, () => setOpen(false));

  useEffect(() => {
    c.getEnvironment().then((e) => setRules(e.organizations ?? null)).catch(() => undefined);
  }, [c]);

  useEffect(() => {
    if (!user) return;
    let live = true;
    Promise.all([c.listOrganizations(), activeOrgId(c.getToken)])
      .then(([list, id]) => {
        if (!live) return;
        setOrgs(list);
        setActive(id);
      })
      .catch((e) => live && setError(message(e)));
    c.listOrgSuggestions().then((l) => live && setSuggestions(l)).catch(() => undefined);
    return () => {
      live = false;
    };
  }, [c, user]);

  if (!user) return null;
  if (rules && !rules.enabled) return null;
  const showPersonal = !hidePersonal && (rules?.allowPersonalAccounts ?? true);
  const canCreate = rules?.allowUserCreation ?? true;
  const current = orgs?.find((o) => o.id === active) ?? null;
  async function select(org: OrgInfo | null) {
    setError(null);
    try {
      await c.setActiveOrganization(org?.id ?? null);
      setActive(org?.id ?? null);
      setOpen(false);
      onChange?.(org);
    } catch (e) {
      setError(message(e));
    }
  }
  return (
    <div ref={ref} className={cx(a, "orgSwitcher", "dw-org-switcher")}>
      <button type="button" aria-haspopup="menu" aria-expanded={open} className={cx(a, "buttonSecondary", "dw-button dw-button-secondary dw-org-current")} onClick={() => setOpen((o) => !o)}>
        {current ? current.name : "Personal account"}
      </button>
      {open && (
        <div role="menu" className={cx(a, "menu", "dw-menu")}>
          {showPersonal && (
            <button role="menuitemradio" aria-checked={!active} type="button" className={cx(a, "menuItem", "dw-menu-item")} onClick={() => void select(null)}>
              Personal account
            </button>
          )}
          {(orgs ?? []).map((o) => (
            <button key={o.id} role="menuitemradio" aria-checked={o.id === active} type="button" className={cx(a, "menuItem", "dw-menu-item")} onClick={() => void select(o)}>
              {o.name} <span className="dw-menu-meta">{o.role}</span>
            </button>
          ))}
          {active && <a role="menuitem" className={cx(a, "menuItem", "dw-menu-item dw-org-manage")} href={c.hostedUrl("organization", window.location.href, { organizationId: active })}>Manage organization</a>}
          {suggestions.map((sg) => (
            <button key={sg.id} type="button" className={cx(a, "menuItem", "dw-menu-item dw-org-suggestion")} onClick={async () => {
              try {
                const org = await c.acceptOrgSuggestion(sg.id);
                setSuggestions((l) => l.filter((x) => x.id !== sg.id));
                setOrgs((l) => [...(l ?? []), org]);
                await select(org);
              } catch (err) {
                setError(message(err));
              }
            }}>
              Join {sg.name} <span className="dw-menu-meta">@{sg.domain}</span>
            </button>
          ))}
          {creating ? (
            <form className="dw-org-create" onSubmit={async (e) => {
              e.preventDefault();
              const name = String(new FormData(e.currentTarget).get("name") ?? "").trim();
              if (!name) return;
              try {
                const org = await c.createOrganization(name);
                setOrgs((l) => [...(l ?? []), org]);
                setCreating(false);
                await select(org);
              } catch (err) {
                setError(message(err));
              }
            }}>
              <input name="name" required maxLength={100} placeholder="Organization name" aria-label="Organization name" className={cx(a, "input", "dw-input")} autoFocus />
              <button className={cx(a, "button", "dw-button dw-button-primary")}>Create</button>
            </form>
          ) : (
            canCreate && <button type="button" className={cx(a, "menuItem", "dw-menu-item dw-org-new")} onClick={() => setCreating(true)}>+ Create organization</button>
          )}
          {error && <Alert a={a}>{error}</Alert>}
        </div>
      )}
    </div>
  );
}

// ---------- <UserProfile /> ----------

const relTime = (iso: string) => {
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 2) return "Active now";
  if (mins < 60) return `${mins} minutes ago`;
  const h = Math.round(mins / 60);
  return h < 48 ? `${h} hours ago` : new Date(iso).toLocaleDateString();
};

/** Edit name, and see and sign out the devices connected to the account. Security settings live on the hosted account page. */
export function UserProfile({ appearance: a, className }: { appearance?: Appearance; className?: string }) {
  const { user } = useUser();
  const c = useAuthClient();
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [msg, setMsg] = useState<{ error?: string; ok?: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const id = useId();

  const reload = () => c.listSessions().then(setSessions).catch(() => undefined);
  useEffect(() => {
    if (user) void reload();
  }, [user?.id]);

  if (!user) return null;

  async function run(fn: () => Promise<string>) {
    setBusy(true);
    setMsg(null);
    try {
      setMsg({ ok: await fn() });
    } catch (e) {
      setMsg({ error: e instanceof Error ? e.message : "Something went wrong" });
    } finally {
      setBusy(false);
    }
  }

  const others = sessions.filter((s) => !s.current).length;
  return (
    <div className={[cx(a, "root", "dw-root dw-profile"), className].filter(Boolean).join(" ")}>
      <form
        className={cx(a, "form", "dw-form")}
        onSubmit={(e: FormEvent<HTMLFormElement>) => {
          e.preventDefault();
          const f = new FormData(e.currentTarget);
          void run(async () => {
            await c.updateProfile({ firstName: (f.get("firstName") as string) || null, lastName: (f.get("lastName") as string) || null });
            return "Profile saved";
          });
        }}
      >
        <h2 className={cx(a, "title", "dw-title")}>Profile</h2>
        <div className={cx(a, "field", "dw-field")}>
          <label htmlFor={`${id}-fn`} className={cx(a, "label", "dw-label")}>First name</label>
          <input id={`${id}-fn`} name="firstName" defaultValue={user.firstName ?? ""} maxLength={100} autoComplete="given-name" className={cx(a, "input", "dw-input")} />
        </div>
        <div className={cx(a, "field", "dw-field")}>
          <label htmlFor={`${id}-ln`} className={cx(a, "label", "dw-label")}>Last name</label>
          <input id={`${id}-ln`} name="lastName" defaultValue={user.lastName ?? ""} maxLength={100} autoComplete="family-name" className={cx(a, "input", "dw-input")} />
        </div>
        <button type="submit" disabled={busy} className={cx(a, "button", "dw-button dw-button-primary")}>Save</button>
      </form>

      <h2 className={cx(a, "title", "dw-title")}>Devices</h2>
      <ul className="dw-sessions">
        {sessions.map((s) => (
          <li key={s.id} className="dw-session">
            <div>
              <div className="dw-session-name">{s.device}{s.current ? " (this device)" : ""}</div>
              <div className="dw-menu-meta">{relTime(s.lastActiveAt)}{s.ipHint ? ` · ${s.ipHint}` : ""}</div>
            </div>
            {!s.current && (
              <button type="button" disabled={busy} className={cx(a, "buttonSecondary", "dw-button dw-button-secondary dw-session-button")} onClick={() => run(async () => { await c.revokeSession(s.id); await reload(); return "Device signed out"; })}>
                Sign out
              </button>
            )}
          </li>
        ))}
      </ul>
      {others > 1 && (
        <button type="button" disabled={busy} className={cx(a, "buttonSecondary", "dw-button dw-button-secondary")} onClick={() => run(async () => { const n = await c.revokeOtherSessions(); await reload(); return `Signed out ${n} other device(s)`; })}>
          Sign out all other devices
        </button>
      )}
      {msg?.error && <p role="alert" className={cx(a, "error", "dw-error")}>{msg.error}</p>}
      {msg?.ok && <p role="status" className={cx(a, "info", "dw-info")}>{msg.ok}</p>}
      <a className={cx(a, "link", "dw-link")} href={c.hostedUrl("account", window.location.href)}>Password, two-factor and passkeys</a>
    </div>
  );
}


// ---------- <CreateOrganization /> ----------

/** A form that creates an organization, makes it the active one, and then calls `onCreated` or goes to `afterCreateUrl`. */
export function CreateOrganization({ appearance: a, className, afterCreateUrl, onCreated }: { appearance?: Appearance; className?: string; afterCreateUrl?: string; onCreated?: (org: OrgInfo) => void }) {
  const c = useAuthClient();
  const { user } = useUser();
  const [rules, setRules] = useState<OrganizationSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const url = useAfterAuthUrl(afterCreateUrl, undefined);
  const id = useId();
  useEffect(() => {
    c.getEnvironment().then((e) => setRules(e.organizations ?? null)).catch(() => undefined);
  }, [c]);
  if (!user) return null;
  if (rules && (!rules.enabled || !rules.allowUserCreation))
    return <Shell a={a} title="Create organization"><Alert a={a}>Creating organizations is turned off for this application.</Alert></Shell>;
  return (
    <div className={[cx(a, "root", "dw-root dw-create-org"), className].filter(Boolean).join(" ")}>
      <div className={cx(a, "header", "dw-header")}>
        <h2 className={cx(a, "title", "dw-title")}>Create organization</h2>
        <p className={cx(a, "subtitle", "dw-subtitle")}>You will be its first member. Invite others afterwards.</p>
      </div>
      <form className={cx(a, "form", "dw-form")} onSubmit={async (e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        const name = String(new FormData(e.currentTarget).get("name") ?? "").trim();
        if (!name) return;
        setBusy(true);
        setError(null);
        try {
          const org = await c.createOrganization(name);
          await c.setActiveOrganization(org.id).catch(() => undefined);
          if (onCreated) onCreated(org);
          else if (url) window.location.assign(url);
        } catch (err) {
          setError(message(err));
        } finally {
          setBusy(false);
        }
      }}>
        <div className={cx(a, "field", "dw-field")}>
          <label htmlFor={`${id}-n`} className={cx(a, "label", "dw-label")}>Organization name</label>
          <input id={`${id}-n`} name="name" required maxLength={80} autoFocus className={cx(a, "input", "dw-input")} />
        </div>
        {error && <Alert a={a}>{error}</Alert>}
        <button type="submit" disabled={busy} className={cx(a, "button", "dw-button dw-button-primary")}>{busy ? "Creating…" : "Create organization"}</button>
      </form>
    </div>
  );
}

// ---------- <OrganizationProfile /> ----------

type OrgTab = "members" | "invitations" | "domains" | "settings";

/** Two clicks for destructive actions, without a browser dialog. */
function Confirm({ a, label, confirmLabel = "Sure?", onConfirm, disabled }: { a?: Appearance; label: string; confirmLabel?: string; onConfirm: () => void; disabled?: boolean }) {
  const [armed, setArmed] = useState(false);
  return (
    <button type="button" disabled={disabled} className={cx(a, "buttonSecondary", `dw-button dw-button-secondary dw-small${armed ? " dw-danger" : ""}`)} onClick={() => { if (armed) { setArmed(false); onConfirm(); } else setArmed(true); }} onBlur={() => setArmed(false)}>
      {armed ? confirmLabel : label}
    </button>
  );
}

const ENROLLMENT_LABEL = { none: "No automatic joining", suggest: "Suggest the organization", auto_join: "Join automatically" } as const;

/**
 * Manage one organization: members and roles, invitations, verified domains, and settings. Tabs show only what
 * your role's permissions allow (the server enforces every action regardless).
 * Pass `organizationId`, or it uses the active organization, else the first one you belong to.
 */
export function OrganizationProfile({ organizationId, appearance: a, className, afterLeaveUrl, onLeave }: { organizationId?: string; appearance?: Appearance; className?: string; afterLeaveUrl?: string; onLeave?: () => void }) {
  const c = useAuthClient();
  const { user } = useUser();
  const [org, setOrg] = useState<OrgInfo | null | undefined>(undefined);
  const [roles, setRoles] = useState<OrgRoleInfo[]>([]);
  const [rules, setRules] = useState<OrganizationSettings | null>(null);
  const [tab, setTab] = useState<OrgTab>("members");
  const [msg, setMsg] = useState<{ error?: string; ok?: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!user) return;
    let live = true;
    Promise.all([c.listOrganizations(), activeOrgId(c.getToken), c.listOrganizationRoles().catch(() => [] as OrgRoleInfo[]), c.getEnvironment().catch(() => null)])
      .then(([list, active, rs, env]) => {
        if (!live) return;
        setRoles(rs);
        setRules(env?.organizations ?? null);
        setOrg((organizationId ? list.find((o) => o.id === organizationId) : (list.find((o) => o.id === active) ?? list[0])) ?? null);
      })
      .catch((e) => {
        if (!live) return;
        setOrg(null);
        setMsg({ error: message(e) });
      });
    return () => { live = false; };
  }, [c, user?.id, organizationId]);

  if (!user || org === undefined) return null;
  if (org === null)
    return <Shell a={a} title="Organization">{msg?.error ? <Alert a={a}>{msg.error}</Alert> : <Alert a={a} tone="info">You are not a member of this organization.</Alert>}</Shell>;

  const perms = org.permissions ?? [];
  const can = (p: string) => perms.includes(p);
  const tabs: [OrgTab, string][] = [["members", "Members"]];
  if (can("invitations:manage")) tabs.push(["invitations", "Invitations"]);
  if (can("org:manage")) tabs.push(["domains", "Domains"], ["settings", "Settings"]);
  const current: OrgTab = tabs.some(([t]) => t === tab) ? tab : "members";
  const role = (key: string) => roles.find((r) => r.key === key)?.name ?? key;
  async function run(fn: () => Promise<string | void>) {
    setBusy(true);
    setMsg(null);
    try {
      const ok = await fn();
      if (ok) setMsg({ ok });
    } catch (e) {
      setMsg({ error: message(e) });
    } finally {
      setBusy(false);
    }
  }
  const leave = () => (onLeave ? onLeave() : afterLeaveUrl ? window.location.assign(afterLeaveUrl) : window.location.reload());
  const props: TabProps = { a, c, org, roles, run, busy, can, role, user, rules, leave, setOrg };

  return (
    <div className={[cx(a, "root", "dw-root dw-org-profile"), className].filter(Boolean).join(" ")}>
      <div className={cx(a, "header", "dw-header")}>
        <h2 className={cx(a, "title", "dw-title")}>{org.name}</h2>
        <p className={cx(a, "subtitle", "dw-subtitle")}>Your role: {role(org.role)}</p>
      </div>
      <div role="tablist" className={cx(a, "tabs", "dw-tabs")}>
        {tabs.map(([t, label]) => (
          <button key={t} role="tab" type="button" aria-selected={t === current} className={cx(a, "tab", "dw-tab")} onClick={() => { setTab(t); setMsg(null); }}>{label}</button>
        ))}
      </div>
      {current === "members" && <OrgMembers {...props} />}
      {current === "invitations" && <OrgInvitations {...props} />}
      {current === "domains" && <OrgDomains {...props} />}
      {current === "settings" && <OrgSettingsTab {...props} />}
      {msg?.error && <Alert a={a}>{msg.error}</Alert>}
      {msg?.ok && <Alert a={a} tone="info">{msg.ok}</Alert>}
    </div>
  );
}

type TabProps = {
  a?: Appearance; c: ReturnType<typeof useAuthClient>; org: OrgInfo; roles: OrgRoleInfo[]; busy: boolean; can: (p: string) => boolean; role: (k: string) => string; user: User;
  rules: OrganizationSettings | null; run: (fn: () => Promise<string | void>) => Promise<void>; leave: () => void; setOrg: (o: OrgInfo) => void;
};

function RoleSelect({ a, roles, value, onChange, disabled, label }: { a?: Appearance; roles: OrgRoleInfo[]; value: string; onChange: (v: string) => void; disabled?: boolean; label: string }) {
  return (
    <select aria-label={label} value={value} disabled={disabled} className={cx(a, "select", "dw-input dw-select")} onChange={(e) => onChange(e.target.value)}>
      {roles.map((r) => <option key={r.key} value={r.key}>{r.name}</option>)}
    </select>
  );
}

function OrgMembers({ a, c, org, roles, busy, can, run, user, leave }: TabProps) {
  const [members, setMembers] = useState<OrgMember[] | null>(null);
  const reload = () => c.listOrgMembers(org.id).then(setMembers).catch((e) => { setMembers([]); void run(async () => { throw e; }); });
  useEffect(() => { void reload(); }, [org.id]);
  const manage = can("members:manage");
  return (
    <div className="dw-section">
      <ul className={cx(a, "list", "dw-list")}>
        {(members ?? []).map((m) => {
          const me = m.userId === user.id;
          const name = m.name ?? [m.firstName, m.lastName].filter(Boolean).join(" ");
          const who = m.email || name || m.userId;
          return (
            <li key={m.userId} className={cx(a, "listItem", "dw-list-item")}>
              <div>
                <div className="dw-session-name">{who}{me ? " (you)" : ""}</div>
                {name && m.email && <div className="dw-menu-meta">{name}</div>}
              </div>
              <div className="dw-actions">
                {manage ? (
                  <RoleSelect a={a} roles={roles} value={m.role} label={`Role of ${who}`} disabled={busy} onChange={(r) => run(async () => { await c.changeOrgRole(org.id, m.userId, r); await reload(); return "Role changed"; })} />
                ) : (
                  <span className="dw-menu-meta">{roles.find((r) => r.key === m.role)?.name ?? m.role}</span>
                )}
                {manage && !me && <Confirm a={a} label="Remove" disabled={busy} onConfirm={() => run(async () => { await c.removeOrgMember(org.id, m.userId); await reload(); return "Member removed"; })} />}
              </div>
            </li>
          );
        })}
      </ul>
      <Confirm a={a} label="Leave organization" confirmLabel="Yes, leave" disabled={busy} onConfirm={() => run(async () => { await c.removeOrgMember(org.id, "me"); leave(); })} />
    </div>
  );
}

function OrgInvitations({ a, c, org, roles, busy, run, rules }: TabProps) {
  const [list, setList] = useState<OrgInvitation[]>([]);
  const [role, setRole] = useState(rules?.defaultRole ?? "member");
  const reload = () => c.listOrgInvitations(org.id).then(setList).catch(() => undefined);
  useEffect(() => { void reload(); }, [org.id]);
  return (
    <div className="dw-section">
      <form className="dw-org-create" onSubmit={(e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        const form = e.currentTarget;
        const email = String(new FormData(form).get("email") ?? "").trim();
        if (email) void run(async () => { await c.inviteToOrg(org.id, email, role); form.reset(); await reload(); return `Invitation sent to ${email}`; });
      }}>
        <input name="email" type="email" required maxLength={254} placeholder="name@company.com" aria-label="Email to invite" className={cx(a, "input", "dw-input")} />
        <RoleSelect a={a} roles={roles} value={role} label="Role for the invitation" onChange={setRole} />
        <button disabled={busy} className={cx(a, "button", "dw-button dw-button-primary dw-small")}>Invite</button>
      </form>
      <ul className={cx(a, "list", "dw-list")}>
        {list.map((i) => (
          <li key={i.id} className={cx(a, "listItem", "dw-list-item")}>
            <div>
              <div className="dw-session-name">{i.email}</div>
              <div className="dw-menu-meta">{roles.find((r) => r.key === i.role)?.name ?? i.role} · expires {new Date(i.expiresAt).toLocaleDateString()}</div>
            </div>
            <Confirm a={a} label="Revoke" disabled={busy} onConfirm={() => run(async () => { await c.revokeOrgInvitation(org.id, i.id); await reload(); return "Invitation revoked"; })} />
          </li>
        ))}
        {!list.length && <li className="dw-menu-meta">No pending invitations.</li>}
      </ul>
    </div>
  );
}

function OrgDomains({ a, c, org, roles, busy, run }: TabProps) {
  const [domains, setDomains] = useState<OrgDomainInfo[]>([]);
  const [code, setCode] = useState<Record<string, string>>({});
  const reload = () => c.listOrgDomains(org.id).then(setDomains).catch(() => undefined);
  useEffect(() => { void reload(); }, [org.id]);
  // Roles that manage the organization are refused for domain joins by the server; don't offer them.
  const joinRoles = roles.filter((r) => r.key !== "admin" && !r.permissions.some((p) => ["org:manage", "members:manage", "invitations:manage"].includes(p)));
  return (
    <div className="dw-section">
      <p className="dw-menu-meta">Prove you own an email domain, then let people with a verified address there find or join this organization.</p>
      <form className="dw-org-create" onSubmit={(e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        const form = e.currentTarget;
        const domain = String(new FormData(form).get("domain") ?? "").trim();
        if (domain) void run(async () => { await c.addOrgDomain(org.id, domain); form.reset(); await reload(); return "Domain added. Verify it below"; });
      }}>
        <input name="domain" required maxLength={253} placeholder="company.com" aria-label="Domain" className={cx(a, "input", "dw-input")} />
        <button disabled={busy} className={cx(a, "button", "dw-button dw-button-primary dw-small")}>Add</button>
      </form>
      <ul className={cx(a, "list", "dw-list")}>
        {domains.map((d) => (
          <li key={d.id} className={cx(a, "listItem", "dw-list-item")}>
            <div className="dw-domain-main">
              <div className="dw-session-name">{d.domain} <span className="dw-badge">{d.verified ? "Verified" : "Unverified"}</span></div>
              {!d.verified && d.dns && (
                <div className="dw-domain-verify">
                  <p className="dw-menu-meta">Add this DNS record, then check it:</p>
                  <code className="dw-code">{d.dns.type} {d.dns.name} = {d.dns.value}</code>
                  <button type="button" disabled={busy} className={cx(a, "buttonSecondary", "dw-button dw-button-secondary dw-small")} onClick={() => run(async () => { await c.verifyOrgDomainDns(org.id, d.id); await reload(); return "Domain verified"; })}>Check DNS record</button>
                  <p className="dw-menu-meta">Or receive a code by email:</p>
                  <div className="dw-org-create">
                    {(["admin", "postmaster"] as const).map((m) => (
                      <button key={m} type="button" disabled={busy} className={cx(a, "buttonSecondary", "dw-button dw-button-secondary dw-small")} onClick={() => run(async () => `Code sent to ${(await c.sendOrgDomainEmail(org.id, d.id, m)).sentTo}`)}>Send to {m}@</button>
                    ))}
                  </div>
                  <div className="dw-org-create">
                    <input inputMode="numeric" maxLength={6} placeholder="6-digit code" aria-label={`Code for ${d.domain}`} value={code[d.id] ?? ""} onChange={(e) => setCode((v) => ({ ...v, [d.id]: e.target.value }))} className={cx(a, "input", "dw-input")} />
                    <button type="button" disabled={busy || (code[d.id] ?? "").length < 6} className={cx(a, "button", "dw-button dw-button-primary dw-small")} onClick={() => run(async () => { await c.verifyOrgDomainEmail(org.id, d.id, code[d.id]); await reload(); return "Domain verified"; })}>Verify</button>
                  </div>
                </div>
              )}
              {d.verified && (
                <div className="dw-org-create">
                  <select aria-label={`Enrollment for ${d.domain}`} value={d.enrollment} disabled={busy} className={cx(a, "select", "dw-input dw-select")} onChange={(e) => run(async () => { await c.updateOrgDomain(org.id, d.id, { enrollment: e.target.value as OrgDomainInfo["enrollment"] }); await reload(); return "Saved"; })}>
                    {Object.entries(ENROLLMENT_LABEL).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
                  </select>
                  <select aria-label={`Role for people joining through ${d.domain}`} value={d.role ?? ""} disabled={busy} className={cx(a, "select", "dw-input dw-select")} onChange={(e) => run(async () => { await c.updateOrgDomain(org.id, d.id, { role: e.target.value || null }); await reload(); return "Saved"; })}>
                    <option value="">Default role</option>
                    {joinRoles.map((r) => <option key={r.key} value={r.key}>{r.name}</option>)}
                  </select>
                </div>
              )}
            </div>
            <Confirm a={a} label="Remove" disabled={busy} onConfirm={() => run(async () => { await c.removeOrgDomain(org.id, d.id); await reload(); return "Domain removed"; })} />
          </li>
        ))}
        {!domains.length && <li className="dw-menu-meta">No domains yet.</li>}
      </ul>
    </div>
  );
}

function OrgSettingsTab({ a, c, org, busy, run, rules, leave, setOrg }: TabProps) {
  const id = useId();
  return (
    <div className="dw-section">
      <form className={cx(a, "form", "dw-form")} onSubmit={(e: FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        const name = String(new FormData(e.currentTarget).get("name") ?? "").trim();
        if (name) void run(async () => { await c.renameOrganization(org.id, name); setOrg({ ...org, name }); return "Name saved"; });
      }}>
        <div className={cx(a, "field", "dw-field")}>
          <label htmlFor={`${id}-n`} className={cx(a, "label", "dw-label")}>Organization name</label>
          <input id={`${id}-n`} name="name" defaultValue={org.name} required maxLength={80} className={cx(a, "input", "dw-input")} />
        </div>
        <button disabled={busy} className={cx(a, "button", "dw-button dw-button-primary")}>Save</button>
      </form>
      <label className={cx(a, "checkbox", "dw-checkbox")}>
        <input type="checkbox" defaultChecked={!!org.requireTwoFactor} disabled={busy} onChange={(e) => run(async () => { await c.setOrganizationTwoFactor(org.id, e.target.checked); setOrg({ ...org, requireTwoFactor: e.target.checked }); return "Saved"; })} />
        <span>Require two-step verification for members</span>
      </label>
      {(rules?.allowAdminDelete ?? true) && (
        <Confirm a={a} label="Delete organization" confirmLabel="Yes, delete it for everyone" disabled={busy} onConfirm={() => run(async () => { await c.deleteOrganization(org.id); leave(); })} />
      )}
    </div>
  );
}

// ---------- Step-up (reverification) ----------

function claimsOf(jwt: string | null) {
  try {
    const p = JSON.parse(atob(jwt!.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return { fva: Array.isArray(p.fva) ? (p.fva as [number, number]) : undefined, issuedAt: Number(p.iat) || 0 };
  } catch {
    return null;
  }
}

type Method = "passkey" | "password" | "email" | "key" | "code";

/**
 * The prompt behind step-up authentication: asks the signed-in person to prove a password, passkey, security key,
 * authenticator/text/backup code or emailed code, depending on what `need` asks for and what their account has.
 * `<AuthProvider>` mounts one for you and `authFetch` opens it when your server answers 403 `reverification_required`;
 * render it yourself for a custom flow. `onDone(true)` once satisfied, `onDone(false)` when they cancel.
 */
export function ReverificationPrompt({ need, onDone, appearance: a }: { need: ReverificationNeed; onDone: (ok: boolean) => void; appearance?: Appearance }) {
  const c = useAuthClient();
  const titleId = useId();
  const [opts, setOpts] = useState<ReverificationOptions | null>(null);
  const [stale, setStale] = useState<{ first: boolean; second: boolean } | null>(null);
  const [method, setMethod] = useState<Method | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [texted, setTexted] = useState(false);
  const [backup, setBackup] = useState(false);
  const done = useRef(onDone);
  done.current = onDone;

  async function refresh() {
    const s = staleFactors(claimsOf(await c.getToken()), need);
    setStale(s);
    if (!s.first && !s.second) done.current(true);
    setMethod(null);
    setError(null);
    return s;
  }
  useEffect(() => {
    void refresh();
    c.getReverificationOptions().then(setOpts).catch((e) => setError(message(e)));
    const esc = (e: KeyboardEvent) => e.key === "Escape" && done.current(false);
    document.addEventListener("keydown", esc);
    return () => document.removeEventListener("keydown", esc);
  }, [c]); // eslint-disable-line react-hooks/exhaustive-deps

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      await refresh();
    } catch (e) {
      if (!(e instanceof AuthError && (e.code === "webauthn_cancelled" || e.code === "passkey_cancelled" || e.code === "security_key_cancelled"))) setError(message(e));
    } finally {
      setBusy(false);
    }
  }

  const first = stale?.first === true;
  const methods: Method[] = !opts || !stale ? [] : first
    ? ([opts.passkey && "passkey", opts.password && "password", opts.emailCode && "email"].filter(Boolean) as Method[])
    : ([opts.passkey && "passkey", opts.securityKey && "key", (opts.totp || opts.sms || opts.backupCodes) && "code"].filter(Boolean) as Method[]);
  const label: Record<Method, string> = { passkey: "Use a passkey", password: "Use your password", email: "Email me a code", key: "Use a security key", code: "Use a verification code" };
  const what = first ? "your password or a passkey" : "your second factor";

  let body: ReactNode;
  if (!opts || !stale) body = error ? <Alert a={a}>{error}</Alert> : <p className={cx(a, "subtitle", "dw-subtitle")}>Loading…</p>;
  else if (!methods.length)
    body = <Alert a={a} tone="info">{first ? "There is no way to verify this account right now." : "This action needs two-step verification, and this account doesn't have it yet. Set it up in your account settings, then try again."}</Alert>;
  else if (!method)
    body = (
      <div className={cx(a, "form", "dw-form")}>
        {methods.map((m) => (
          <button key={m} type="button" disabled={busy} className={cx(a, "buttonSecondary", "dw-button dw-button-secondary")} onClick={() => {
            if (m === "passkey") void run(() => c.reverifyWithPasskey());
            else if (m === "key") void run(() => c.reverifyWithSecurityKey());
            else if (m === "email") { setMethod(m); void c.sendReverificationEmailCode().then(() => setSent(true)).catch((e) => setError(message(e))); }
            else setMethod(m);
          }}>{label[m]}</button>
        ))}
        {error && <Alert a={a}>{error}</Alert>}
      </div>
    );
  else
    body = (
      <form className={cx(a, "form", "dw-form")} noValidate onSubmit={(e) => {
        e.preventDefault();
        const v = String(new FormData(e.currentTarget).get("value") ?? "");
        void run(() => (method === "password" ? c.reverifyWithPassword(v) : method === "email" ? c.reverifyWithEmailCode(v) : c.reverifyWithCode(v, !backup && texted ? "sms" : undefined)));
      }}>
        {method === "email" && <p className={cx(a, "subtitle", "dw-subtitle")}>{sent ? "We emailed you a code." : "Sending a code…"}</p>}
        {method === "code" && <p className={cx(a, "subtitle", "dw-subtitle")}>{backup ? "Enter one of your backup codes." : texted ? `Enter the code we texted to ${opts.sms}.` : "Enter the code from your authenticator app."}</p>}
        <Field a={a} key={method + String(backup)} label={method === "password" ? "Password" : method === "email" ? "Emailed code" : backup ? "Backup code" : "Verification code"} name="value" type={method === "password" ? "password" : "text"} autoComplete={method === "password" ? "current-password" : "one-time-code"} inputMode={method === "password" || backup ? undefined : "numeric"} maxLength={method === "password" ? 256 : 20} required autoFocus />
        {error && <Alert a={a}>{error}</Alert>}
        <button disabled={busy} className={cx(a, "button", "dw-button dw-button-primary")}>{busy ? "Please wait…" : "Verify"}</button>
        {method === "code" && opts.sms && !backup && (
          <button type="button" className={cx(a, "link", "dw-link")} onClick={() => c.sendSecondFactorSms().then(() => setTexted(true)).catch((e) => setError(message(e)))}>{texted ? "Send another code" : `Text a code to ${opts.sms}`}</button>
        )}
        {method === "code" && opts.backupCodes && (
          <button type="button" className={cx(a, "link", "dw-link")} onClick={() => setBackup((b) => !b)}>{backup ? "Use your authenticator app" : "Use a backup code"}</button>
        )}
        <button type="button" className={cx(a, "link", "dw-link")} onClick={() => { setMethod(null); setError(null); }}>Choose another way</button>
      </form>
    );

  return (
    <div className={cx(a, "modalBackdrop", "dw-modal-backdrop")} onMouseDown={(e) => e.target === e.currentTarget && done.current(false)}>
      <div role="dialog" aria-modal="true" aria-labelledby={titleId} className={cx(a, "root", "dw-root dw-modal")}>
        <div className={cx(a, "header", "dw-header")}>
          <h2 id={titleId} className={cx(a, "title", "dw-title")}>Confirm it's you</h2>
          <p className={cx(a, "subtitle", "dw-subtitle")}>For your security, please verify {what} to continue.</p>
        </div>
        {body}
        <button type="button" className={cx(a, "link", "dw-link")} onClick={() => done.current(false)}>Cancel</button>
      </div>
    </div>
  );
}

/** Registers the prompt with the client and shows it whenever `authFetch` needs it. Mounted by `<AuthProvider>`. */
export function ReverificationHost({ appearance }: { appearance?: Appearance }) {
  const c = useAuthClient();
  const [pending, setPending] = useState<{ need: ReverificationNeed; settle: (ok: boolean) => void } | null>(null);
  useEffect(() => {
    let shared: Promise<boolean> | null = null; // concurrent failing requests share one prompt
    return c.setReverificationHandler((need) => (shared ??= new Promise<boolean>((resolve) => {
      setPending({ need, settle: (ok) => { shared = null; setPending(null); resolve(ok); } });
    })));
  }, [c]);
  return pending ? <ReverificationPrompt need={pending.need} onDone={pending.settle} appearance={appearance} /> : null;
}
