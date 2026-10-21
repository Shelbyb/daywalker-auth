"use client";

import { useState } from "react";
import Link from "next/link";
import { AuthError } from "@daywalker/auth";
import { hostedClient } from "./hosted-client";
import { CodeInput, Submit, Alert } from "./code-input";

/** Two steps: request a code, then set a new password with it. */
export function ForgotPassword({ pk, redirect }: { pk: string; redirect?: string }) {
  const [email, setEmail] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);
  const signInHref = `/sign-in?pk=${encodeURIComponent(pk)}${redirect ? `&redirect_url=${encodeURIComponent(redirect)}` : ""}`;

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
    } catch (e) {
      setError(e instanceof AuthError ? e.message : "Network error. Try again.");
    } finally {
      setBusy(false);
    }
  }

  if (done)
    return (
      <div className="space-y-4 text-center">
        <p className="font-medium">Password updated</p>
        <p className="text-sm text-stone-500">For your security you&apos;ve been signed out on all devices.</p>
        <Link href={signInHref} className="inline-block text-sm font-medium underline-offset-4 hover:underline">
          Sign in with your new password
        </Link>
      </div>
    );

  if (!email)
    return (
      <form
        className="space-y-4"
        onSubmit={(e) => {
          e.preventDefault();
          const value = String(new FormData(e.currentTarget).get("email") ?? "");
          void run(async () => {
            await hostedClient(pk).requestPasswordReset(value);
            setEmail(value);
          });
        }}
      >
        <label className="block">
          <span className="mb-1 block text-sm font-medium text-stone-700">Email</span>
          <input name="email" type="email" autoComplete="email" required maxLength={254}
            className="w-full rounded-lg border border-stone-300 bg-white px-3 py-2 text-sm outline-none focus:border-dawn focus:ring-2 focus:ring-dawn/30" />
        </label>
        {error && <Alert>{error}</Alert>}
        <Submit busy={busy}>Send reset code</Submit>
        <Link href={signInHref} className="block text-center text-sm text-stone-500 hover:text-ink">Back to sign in</Link>
      </form>
    );

  return (
    <form
      className="space-y-4"
      onSubmit={(e) => {
        e.preventDefault();
        const f = new FormData(e.currentTarget);
        void run(async () => {
          await hostedClient(pk).resetPassword({ email, code: String(f.get("code")), password: String(f.get("password")) });
          setDone(true);
        });
      }}
    >
      {/* Same message either way, so this page doesn't reveal which emails have accounts. */}
      <Alert tone="info">If {email} has an account, a code is on its way.</Alert>
      <CodeInput />
      <label className="block">
        <span className="mb-1 block text-sm font-medium text-stone-700">New password</span>
        <input name="password" type="password" autoComplete="new-password" required maxLength={256}
          className="w-full rounded-lg border border-stone-300 bg-white px-3 py-2 text-sm outline-none focus:border-dawn focus:ring-2 focus:ring-dawn/30" />
      </label>
      {error && <Alert>{error}</Alert>}
      <Submit busy={busy}>Set new password</Submit>
    </form>
  );
}
