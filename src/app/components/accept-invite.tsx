"use client";

import { useEffect, useState } from "react";
import { AuthError } from "@daywalker/auth";
import { hostedClient } from "./hosted-client";
import { Submit, Alert } from "./code-input";

type Preview = { orgName: string; role: string };

/** Shows what the invite is for, then joins once the signed-in (and verified) invitee confirms. */
export function AcceptInvite({ pk, token, appName, redirect }: { pk: string; token: string; appName: string; redirect?: string }) {
  const [preview, setPreview] = useState<Preview | null>(null);
  const [signedIn, setSignedIn] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [joined, setJoined] = useState<string | null>(null);

  useEffect(() => {
    const c = hostedClient(pk);
    c.previewInvitation(token).then(setPreview).catch((e) => setError(e instanceof AuthError ? e.message : "Network error. Try again."));
    c.load().then(() => setSignedIn(!!c.state.sessionId));
  }, [pk, token]);

  const here = `/accept-invite?pk=${encodeURIComponent(pk)}&token=${encodeURIComponent(token)}${redirect ? `&redirect_url=${encodeURIComponent(redirect)}` : ""}`;
  const authHref = (page: "sign-in" | "sign-up") => `/${page}?pk=${encodeURIComponent(pk)}&redirect_url=${encodeURIComponent(here)}`;

  async function accept() {
    setBusy(true);
    setError(null);
    try {
      const org = await hostedClient(pk).acceptInvitation(token);
      setJoined(org.name);
      if (redirect) setTimeout(() => (window.location.href = redirect), 1200);
    } catch (e) {
      setError(e instanceof AuthError ? e.message : "Network error. Try again.");
    } finally {
      setBusy(false);
    }
  }

  if (joined)
    return (
      <div className="space-y-2 text-center">
        <h1 className="text-xl font-semibold">You&apos;re in</h1>
        <p className="text-sm text-stone-500">You joined {joined}.</p>
      </div>
    );
  if (!preview) return error ? <Alert>{error}</Alert> : <p className="text-center text-sm text-stone-500">Loading invitation…</p>;

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Join {preview.orgName}</h1>
      <p className="text-sm text-stone-500">
        You&apos;ve been invited to {preview.orgName} on {appName} as {preview.role === "admin" ? "an admin" : "a member"}.
      </p>
      {error && <Alert>{error}</Alert>}
      {signedIn === null ? null : signedIn ? (
        <form onSubmit={(e) => { e.preventDefault(); void accept(); }}><Submit busy={busy}>Accept invitation</Submit></form>
      ) : (
        <div className="space-y-2 text-sm">
          <p className="text-stone-500">Sign in with the invited email address to continue.</p>
          <a className="block rounded-lg bg-ink px-4 py-2 text-center font-medium text-white" href={authHref("sign-in")}>Sign in</a>
          <a className="block text-center text-stone-500 hover:text-ink" href={authHref("sign-up")}>Create an account</a>
        </div>
      )}
    </div>
  );
}
