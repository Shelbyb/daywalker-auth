"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AuthError } from "@daywalker/auth";
import { hostedClient } from "./hosted-client";
import { VerifyEmailStep } from "./verify-email";
import { SecondFactorStep } from "./second-factor";

type Mode = "sign-in" | "sign-up";
type Field = { name: string; label: string; type: string; autoComplete: string; required?: boolean };

const FIELDS: Record<Mode, Field[]> = {
  "sign-in": [
    { name: "email", label: "Email", type: "email", autoComplete: "email", required: true },
    { name: "password", label: "Password", type: "password", autoComplete: "current-password", required: true },
  ],
  "sign-up": [
    { name: "firstName", label: "First name", type: "text", autoComplete: "given-name" },
    { name: "lastName", label: "Last name", type: "text", autoComplete: "family-name" },
    { name: "email", label: "Email", type: "email", autoComplete: "email", required: true },
    { name: "password", label: "Password", type: "password", autoComplete: "new-password", required: true },
  ],
};

/**
 * `redirect` arrives already validated by the server page (same-origin path or an origin on
 * the instance's allow-list), so this form can't be used as an open redirect.
 */
// Fixed messages for codes the OAuth callback puts in the URL; nothing from the URL is shown verbatim.
const OAUTH_ERRORS: Record<string, string> = {
  oauth_cancelled: "Sign-in was cancelled.",
  oauth_failed: "We couldn't sign you in with that provider. Please try again.",
  email_unverified: "That account has no verified email address. Verify it with the provider, or sign in with email.",
  provider_disabled: "That sign-in option isn't available for this app.",
  forbidden: "This account is suspended.",
  legal_required: "Please accept the terms to create an account.",
};

export type LegalInfo = { required: boolean; termsUrl: string | null; privacyUrl: string | null };

const PROVIDER_LABEL = { google: "Google", github: "GitHub" } as const;

export function AuthForm({
  mode,
  pk,
  redirect,
  providers = [],
  initialError,
  signedIn,
  legal,
}: {
  mode: Mode;
  pk: string;
  redirect?: string;
  providers?: ("google" | "github")[];
  initialError?: string;
  signedIn?: boolean;
  legal?: LegalInfo;
}) {
  const [error, setError] = useState<string | null>(initialError ? (OAUTH_ERRORS[initialError] ?? null) : null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState<{ name: string } | null>(signedIn ? { name: "" } : null);
  const [verifying, setVerifying] = useState(false);
  const [needsSecondFactor, setNeedsSecondFactor] = useState(false);
  // Never pre-ticked: consent has to be an active choice.
  const [accepted, setAccepted] = useState(false);
  const needsConsent = mode === "sign-up" && !!legal?.required;
  // Decided after mount: passkey support can only be detected in the browser.
  const [canUsePasskey, setCanUsePasskey] = useState(false);
  useEffect(() => setCanUsePasskey(mode === "sign-in" && hostedClient(pk).passkeysSupported()), [mode, pk]);

  async function passkeySignIn() {
    setBusy(true);
    setError(null);
    try {
      const { user } = await hostedClient(pk).signInWithPasskey();
      if (redirect) window.location.assign(redirect);
      else setDone({ name: user.firstName || user.emailAddresses[0]?.email || "" });
    } catch (err) {
      // Closing the prompt isn't an error worth shouting about.
      if (err instanceof AuthError && err.code !== "passkey_cancelled") setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setFieldErrors({});
    const body = Object.fromEntries(new FormData(e.currentTarget)) as Record<string, string>;
    const client = hostedClient(pk);
    try {
      let user;
      if (mode === "sign-in") {
        const result = await client.signIn({ email: body.email, password: body.password });
        if (result.status === "needs_second_factor") {
          setNeedsSecondFactor(true);
          return;
        }
        user = result.user;
      } else {
        user = await client.signUp({
          email: body.email,
          password: body.password,
          firstName: body.firstName || undefined,
          lastName: body.lastName || undefined,
          legalAccepted: needsConsent ? accepted : undefined,
        });
      }
      if (mode === "sign-up" && !user.emailAddresses[0]?.verified) {
        // Confirm the address before continuing; the code is sent as the step opens.
        setVerifying(true);
        return;
      }
      if (redirect) window.location.assign(redirect);
      else setDone({ name: user.firstName || user.emailAddresses[0]?.email || "" });
    } catch (err) {
      if (err instanceof AuthError) {
        setError(err.message);
        setFieldErrors(Object.fromEntries(err.fields.map((f) => [f.path, f.message])));
      } else setError("Network error. Check your connection and try again.");
    } finally {
      setBusy(false);
    }
  }

  if (needsSecondFactor)
    return <SecondFactorStep pk={pk} onDone={(name) => (redirect ? window.location.assign(redirect) : setDone({ name }))} />;

  if (verifying)
    return (
      <VerifyEmailStep
        pk={pk}
        onVerified={(name) => (redirect ? window.location.assign(redirect) : setDone({ name }))}
      />
    );

  if (done)
    return (
      <div className="text-center">
        <p className="text-lg font-medium">You&apos;re signed in</p>
        {done.name && <p className="mt-1 text-sm text-stone-500">Welcome, {done.name}.</p>}
      </div>
    );

  const other = mode === "sign-in" ? "sign-up" : "sign-in";
  const consentBox = needsConsent && (
    <label className="flex items-start gap-2 text-sm text-stone-600">
      <input type="checkbox" checked={accepted} onChange={(e) => setAccepted(e.target.checked)} className="mt-0.5 h-4 w-4 accent-ink" />
      <span>
        I agree to the{" "}
        <a href={legal!.termsUrl!} target="_blank" rel="noopener noreferrer" className="font-medium text-ink underline underline-offset-2">Terms of Service</a>
        {legal!.privacyUrl && (
          <>
            {" "}and{" "}
            <a href={legal!.privacyUrl} target="_blank" rel="noopener noreferrer" className="font-medium text-ink underline underline-offset-2">Privacy Policy</a>
          </>
        )}
      </span>
    </label>
  );
  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      {consentBox}
      {(providers.length > 0 || canUsePasskey) && (
        <>
          <div className="grid gap-2">
            {canUsePasskey && (
              <button
                type="button"
                onClick={passkeySignIn}
                disabled={busy}
                className="w-full rounded-lg border border-stone-300 bg-white px-4 py-2.5 text-sm font-medium transition hover:bg-stone-50 disabled:opacity-60"
              >
                Sign in with a passkey
              </button>
            )}
            {providers.map((p) => (
              <button
                key={p}
                type="button"
                disabled={needsConsent && !accepted}
                title={needsConsent && !accepted ? "Accept the terms first" : undefined}
                onClick={() =>
                  hostedClient(pk).signInWithOAuth(p, redirect ?? `${window.location.origin}/sign-in?pk=${encodeURIComponent(pk)}&status=signed_in`, {
                    legalAccepted: mode === "sign-up" && accepted,
                  })
                }
                className="w-full rounded-lg border border-stone-300 bg-white px-4 py-2.5 text-sm font-medium transition hover:bg-stone-50 disabled:cursor-not-allowed disabled:opacity-50"
              >
                Continue with {PROVIDER_LABEL[p]}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-3 text-xs text-stone-400">
            <span className="h-px flex-1 bg-stone-200" />or<span className="h-px flex-1 bg-stone-200" />
          </div>
        </>
      )}
      <div className={mode === "sign-up" ? "grid grid-cols-2 gap-3" : ""}>
        {FIELDS[mode].slice(0, mode === "sign-up" ? 2 : 0).map((f) => (
          <Input key={f.name} field={f} error={fieldErrors[f.name]} />
        ))}
      </div>
      {FIELDS[mode].slice(mode === "sign-up" ? 2 : 0).map((f) => (
        <Input key={f.name} field={f} error={fieldErrors[f.name]} />
      ))}
      {mode === "sign-in" && (
        <Link
          href={`/forgot-password?pk=${encodeURIComponent(pk)}${redirect ? `&redirect_url=${encodeURIComponent(redirect)}` : ""}`}
          className="block text-right text-xs text-stone-500 hover:text-ink"
        >
          Forgot password?
        </Link>
      )}
      {error && (
        <p role="alert" className="rounded-lg bg-ember/10 px-3 py-2 text-sm text-ember">
          {error}
        </p>
      )}
      <button
        disabled={busy || (needsConsent && !accepted)}
        className="w-full rounded-lg bg-ink px-4 py-2.5 text-sm font-medium text-white transition hover:bg-dusk disabled:opacity-60"
      >
        {busy ? "Please wait…" : mode === "sign-in" ? "Continue" : "Create account"}
      </button>
      <p className="text-center text-sm text-stone-500">
        {mode === "sign-in" ? "No account yet? " : "Already have an account? "}
        <Link
          href={`/${other}?pk=${encodeURIComponent(pk)}${redirect ? `&redirect_url=${encodeURIComponent(redirect)}` : ""}`}
          className="font-medium text-ink underline-offset-4 hover:underline"
        >
          {mode === "sign-in" ? "Sign up" : "Sign in"}
        </Link>
      </p>
    </form>
  );
}

function Input({ field, error }: { field: Field; error?: string }) {
  return (
    <label className="block">
      <span className="mb-1 block text-sm font-medium text-stone-700">{field.label}</span>
      <input
        name={field.name}
        type={field.type}
        autoComplete={field.autoComplete}
        required={field.required}
        maxLength={field.type === "password" ? 256 : 254}
        aria-invalid={!!error}
        className="w-full rounded-lg border border-stone-300 bg-white px-3 py-2 text-sm outline-none transition focus:border-dawn focus:ring-2 focus:ring-dawn/30 aria-[invalid=true]:border-ember"
      />
      {error && <span className="mt-1 block text-xs text-ember">{error}</span>}
    </label>
  );
}
