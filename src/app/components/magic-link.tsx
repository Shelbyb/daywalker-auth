"use client";

import { useEffect, useState } from "react";
import { AuthError } from "@daywalker/auth";
import { hostedClient } from "./hosted-client";
import { Alert, Submit } from "./code-input";
import { SecondFactorStep } from "./second-factor";

/**
 * Landing page for sign-in links. The token is in the URL fragment (never sent to a server) and
 * is removed from the address bar at once. Signing in needs a click, so link scanners in mail
 * systems that open links can't use the token up.
 */
export function MagicLink({ pk, appName }: { pk: string; appName: string }) {
  const [token, setToken] = useState<string | null | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [needsSecondFactor, setNeedsSecondFactor] = useState(false);
  const [redirect, setRedirect] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  useEffect(() => {
    const t = new URLSearchParams(window.location.hash.slice(1)).get("token");
    setToken(t);
    if (t) history.replaceState(null, "", window.location.pathname + window.location.search);
  }, []);

  const finish = (name: string, to: string | null) => (to ? window.location.assign(to) : setDone(name));

  async function go() {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      const r = await hostedClient(pk).signInWithMagicLink(token);
      if (r.status === "needs_second_factor") {
        setRedirect(r.redirectUrl);
        setNeedsSecondFactor(true);
      } else finish(r.user.firstName || r.user.emailAddresses[0]?.email || "", r.redirectUrl);
    } catch (err) {
      setError(err instanceof AuthError ? err.message : "Network error. Check your connection and try again.");
      setToken(null);
    } finally {
      setBusy(false);
    }
  }

  if (needsSecondFactor) return <SecondFactorStep pk={pk} onDone={(name) => finish(name, redirect)} />;
  if (done !== null)
    return (
      <div className="text-center">
        <p className="text-lg font-medium">You&apos;re signed in</p>
        {done && <p className="mt-1 text-sm text-stone-500">Welcome, {done}.</p>}
      </div>
    );
  if (token === undefined) return null;
  if (!token)
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-semibold">Sign-in link</h1>
        <Alert>{error ?? "This link is incomplete. Open the link from your email again, or request a new one."}</Alert>
        <a href={`/sign-in?pk=${encodeURIComponent(pk)}`} className="block text-center text-sm font-medium text-ink underline-offset-4 hover:underline">
          Back to sign in
        </a>
      </div>
    );
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Sign in to {appName}</h1>
      <p className="text-sm text-stone-500">Continue to finish signing in on this device. The link works once.</p>
      {error && <Alert>{error}</Alert>}
      <form onSubmit={(e) => { e.preventDefault(); void go(); }}>
        <Submit busy={busy}>Continue</Submit>
      </form>
    </div>
  );
}
