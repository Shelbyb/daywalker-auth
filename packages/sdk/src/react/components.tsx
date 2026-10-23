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
import { AuthError, type OAuthProvider, type OrgInfo, type User } from "../core/client";
import { useAuthClient, useUser } from "./index";

export type Appearance = {
  /** Extra classes per part, e.g. { button: "btn btn-primary", input: "form-control" }. */
  classNames?: Partial<Record<Part, string>>;
};
type Part =
  | "root" | "header" | "title" | "subtitle" | "form" | "field" | "label" | "input" | "button" | "buttonSecondary"
  | "providers" | "divider" | "error" | "info" | "footer" | "link" | "checkbox"
  | "userButton" | "avatar" | "menu" | "menuItem" | "orgSwitcher";

const cx = (appearance: Appearance | undefined, part: Part, base: string) => [base, appearance?.classNames?.[part]].filter(Boolean).join(" ");

export type EnvironmentInfo = {
  name: string;
  oauthProviders: OAuthProvider[];
  oauthProviderLabels: Partial<Record<OAuthProvider, string>>;
  passwordMinLength: number;
  emailCodeSignIn: boolean;
  ssoEnabled?: boolean;
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

/** Renders the widget; `onToken` gets each answer (or null when it expires). Change `round` to get a fresh one. */
function Captcha({ siteKey, onToken, round }: { siteKey: string; onToken: (t: string | null) => void; round: number }) {
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
        id = t.render(ref.current, { sitekey: siteKey, callback: (tok: string) => cb.current(tok), "expired-callback": () => cb.current(null), "error-callback": () => cb.current(null) });
      })
      .catch(() => undefined);
    return () => {
      live = false;
      if (api && id) api.remove(id);
    };
  }, [siteKey, round]);
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
};

// ---------- Small building blocks ----------

function Field(props: { a?: Appearance; label: string; name: string; type?: string; autoComplete?: string; required?: boolean; value?: string; onChange?: (v: string) => void; inputMode?: "numeric"; maxLength?: number; autoFocus?: boolean }) {
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

function Shell({ a, title, subtitle, children, footer }: { a?: Appearance; title: string; subtitle?: string; children: ReactNode; footer?: ReactNode }) {
  return (
    <div className={cx(a, "root", "dw-root")}>
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

export function SignIn({ redirectUrl, onSignedIn, appearance: a, signUpUrl, initialEnvironment, initialError, signedIn }: CommonProps & { /** Link for "No account yet?". */ signUpUrl?: string }) {
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

  const done = (u: User) => {
    setDoneUser(u);
    if (c.state.twoFactorSetupRequired) return setStep("setup"); // the app requires two-step verification first
    setStep("done");
    finish(redirectUrl, onSignedIn, u);
  };
  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (err) {
      if (!(err instanceof AuthError && err.code === "passkey_cancelled")) setError(message(err));
    } finally {
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
            {env.captcha && <Captcha siteKey={env.captcha.siteKey} onToken={setCaptchaToken} round={captchaRound} />}
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
    <Shell a={a} title="Sign in" subtitle={`to continue to ${env.name}`} footer={footer}>
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
          const r = await c.signIn({ email: String(f.get("email") ?? ""), password: String(f.get("password") ?? "") });
          if (r.status === "needs_second_factor") setStep("second-factor");
          else done(r.user);
        });
      }}>
        <Field a={a} label="Email" name="email" type="email" autoComplete="email" required value={email} onChange={setEmail} />
        <Field a={a} label="Password" name="password" type="password" autoComplete="current-password" required maxLength={256} />
        <a href={c.hostedUrl("forgot-password", redirectUrl ?? window.location.href)} className={cx(a, "link", "dw-link dw-forgot")}>Forgot password?</a>
        {error && <Alert a={a}>{error}</Alert>}
        <button disabled={busy} className={cx(a, "button", "dw-button dw-button-primary")}>{busy ? "Please wait…" : "Continue"}</button>
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

export function SignUp({ redirectUrl, onSignedIn, appearance: a, signInUrl, initialEnvironment, initialError, signedIn }: CommonProps & { /** Link for "Already have an account?". */ signInUrl?: string }) {
  const c = useAuthClient();
  const { env, failed } = useEnvironment(initialEnvironment);
  const [step, setStep] = useState<"form" | "verify" | "setup" | "done">(signedIn ? "done" : "form");
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
    <Shell a={a} title="Create your account" subtitle={`to continue to ${env.name}`} footer={footer}>
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
        {env.captcha && <Captcha siteKey={env.captcha.siteKey} onToken={setCaptchaToken} round={captchaRound} />}
        {Object.values(fieldErrors)[0] && <Alert a={a}>{Object.values(fieldErrors)[0]}</Alert>}
        {error && !Object.keys(fieldErrors).length && <Alert a={a}>{error}</Alert>}
        <button disabled={busy || (needsConsent && !accepted) || (!!env.captcha && !captchaToken)} className={cx(a, "button", "dw-button dw-button-primary")}>{busy ? "Please wait…" : "Create account"}</button>
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
  const ref = useDismiss(open, () => setOpen(false));

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
    return () => {
      live = false;
    };
  }, [c, user]);

  if (!user) return null;
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
          {!hidePersonal && (
            <button role="menuitemradio" aria-checked={!active} type="button" className={cx(a, "menuItem", "dw-menu-item")} onClick={() => void select(null)}>
              Personal account
            </button>
          )}
          {(orgs ?? []).map((o) => (
            <button key={o.id} role="menuitemradio" aria-checked={o.id === active} type="button" className={cx(a, "menuItem", "dw-menu-item")} onClick={() => void select(o)}>
              {o.name} <span className="dw-menu-meta">{o.role}</span>
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
            <button type="button" className={cx(a, "menuItem", "dw-menu-item dw-org-new")} onClick={() => setCreating(true)}>+ Create organization</button>
          )}
          {error && <Alert a={a}>{error}</Alert>}
        </div>
      )}
    </div>
  );
}
