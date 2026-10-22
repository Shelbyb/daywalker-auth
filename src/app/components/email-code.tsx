"use client";

import { useState } from "react";
import { AuthError } from "@daywalker/auth";
import { hostedClient } from "./hosted-client";
import { Alert, CodeInput, Submit } from "./code-input";
import { SecondFactorStep } from "./second-factor";

/** Passwordless sign-in: send a code (and link) to an email, then type the code. */
export function EmailCodeStep({
  pk,
  initialEmail = "",
  redirect,
  onDone,
  onBack,
}: {
  pk: string;
  initialEmail?: string;
  redirect?: string;
  onDone: (name: string) => void;
  onBack: () => void;
}) {
  const [email, setEmail] = useState(initialEmail);
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [needsSecondFactor, setNeedsSecondFactor] = useState(false);

  const fail = (err: unknown) => setError(err instanceof AuthError ? err.message : "Network error. Check your connection and try again.");

  async function send(e?: React.FormEvent<HTMLFormElement>) {
    e?.preventDefault();
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      await hostedClient(pk).sendSignInCode({ email, redirectUrl: redirect });
      setSent(true);
      setInfo(`If ${email} has an account, we've sent it a code and a sign-in link. They expire in 10 minutes.`);
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  }

  async function verify(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const r = await hostedClient(pk).signInWithEmailCode({ email, code: String(new FormData(e.currentTarget).get("code") ?? "") });
      if (r.status === "needs_second_factor") setNeedsSecondFactor(true);
      else onDone(r.user.firstName || r.user.emailAddresses[0]?.email || "");
    } catch (err) {
      fail(err);
    } finally {
      setBusy(false);
    }
  }

  if (needsSecondFactor) return <SecondFactorStep pk={pk} onDone={onDone} />;

  if (!sent)
    return (
      <form onSubmit={send} className="space-y-4">
        <h2 className="text-lg font-semibold">Sign in with an email code</h2>
        <p className="text-sm text-stone-500">We&apos;ll email you a 6-digit code and a link. No password needed.</p>
        <label className="block">
          <span className="mb-1 block text-sm font-medium text-stone-700">Email</span>
          <input
            type="email"
            required
            autoFocus
            autoComplete="email"
            maxLength={254}
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full rounded-lg border border-stone-300 bg-white px-3 py-2 text-sm outline-none transition focus:border-dawn focus:ring-2 focus:ring-dawn/30"
          />
        </label>
        {error && <Alert>{error}</Alert>}
        <Submit busy={busy}>Email me a code</Submit>
        <button type="button" onClick={onBack} className="w-full text-center text-sm text-stone-500 hover:text-ink">
          Use a password instead
        </button>
      </form>
    );

  return (
    <form onSubmit={verify} className="space-y-4">
      <h2 className="text-lg font-semibold">Check your email</h2>
      {info && <Alert tone="info">{info}</Alert>}
      <CodeInput />
      {error && <Alert>{error}</Alert>}
      <Submit busy={busy}>Sign in</Submit>
      <div className="flex justify-between text-sm text-stone-500">
        <button type="button" onClick={() => { setSent(false); setError(null); }} className="hover:text-ink">Change email</button>
        <button type="button" disabled={busy} onClick={() => send()} className="hover:text-ink disabled:opacity-60">Send a new code</button>
      </div>
    </form>
  );
}
