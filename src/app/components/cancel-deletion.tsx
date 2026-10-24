"use client";

import { useEffect, useState } from "react";
import { AuthError } from "@daywalker/auth";
import { hostedClient } from "./hosted-client";
import { Alert, Submit } from "./code-input";

/** Landing page for the cancel-deletion link. The token is in the fragment and removed at once; canceling needs a click. */
export function CancelDeletion({ pk, appName }: { pk: string; appName: string }) {
  const [token, setToken] = useState<string | null | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  useEffect(() => {
    const t = new URLSearchParams(window.location.hash.slice(1)).get("token");
    setToken(t);
    if (t) history.replaceState(null, "", window.location.pathname + window.location.search);
  }, []);

  async function go() {
    if (!token) return;
    setBusy(true);
    setError(null);
    try {
      await hostedClient(pk).cancelAccountDeletion(token);
      setDone(true);
    } catch (err) {
      setError(err instanceof AuthError ? err.message : "Network error. Check your connection and try again.");
      setToken(null);
    } finally {
      setBusy(false);
    }
  }

  if (token === undefined) return null;
  if (done)
    return (
      <div className="space-y-4 text-center">
        <p className="text-lg font-medium">Deletion canceled</p>
        <a href={`/sign-in?pk=${encodeURIComponent(pk)}`} className="block text-sm font-medium text-ink underline-offset-4 hover:underline">Continue to sign in</a>
      </div>
    );
  if (!token)
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-semibold">CancelDeletion account</h1>
        <Alert>{error ?? "This link is incomplete. Open the link from your email again."}</Alert>
        <a href={`/sign-in?pk=${encodeURIComponent(pk)}`} className="block text-center text-sm font-medium text-ink underline-offset-4 hover:underline">Back to sign in</a>
      </div>
    );
  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">CancelDeletion your {appName} account</h1>
      <p className="text-sm text-stone-500">Your account is scheduled for deletion. Continue to cancel the deletion and keep it, then sign in. The link works once.</p>
      {error && <Alert>{error}</Alert>}
      <form onSubmit={(e) => { e.preventDefault(); void go(); }}>
        <Submit busy={busy}>CancelDeletion account</Submit>
      </form>
    </div>
  );
}
