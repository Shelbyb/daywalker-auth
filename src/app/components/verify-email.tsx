"use client";

import { useEffect, useRef, useState } from "react";
import { AuthError } from "@daywalker/auth";
import { hostedClient } from "./hosted-client";
import { CodeInput, Submit, Alert } from "./code-input";

export function VerifyEmailStep({ pk, onVerified }: { pk: string; onVerified: (name: string) => void }) {
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const sent = useRef(false);
  const client = hostedClient(pk);
  const email = client.state.user?.emailAddresses[0]?.email;

  async function send() {
    setError(null);
    try {
      await client.sendVerificationCode();
      setInfo(`We sent a 6-digit code to ${email}.`);
    } catch (e) {
      setError(e instanceof AuthError ? e.message : "Couldn't send the code. Try again.");
    }
  }

  useEffect(() => {
    if (sent.current) return; // StrictMode runs effects twice in dev
    sent.current = true;
    void send();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const user = await client.verifyEmail(String(new FormData(e.currentTarget).get("code") ?? ""));
      onVerified(user.firstName || user.emailAddresses[0]?.email || "");
    } catch (err) {
      setError(err instanceof AuthError ? err.message : "Network error. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <h2 className="text-lg font-semibold">Check your email</h2>
      {info && <Alert tone="info">{info}</Alert>}
      <CodeInput />
      {error && <Alert>{error}</Alert>}
      <Submit busy={busy}>Verify email</Submit>
      <button type="button" onClick={send} className="w-full text-center text-sm text-stone-500 hover:text-ink">
        Resend code
      </button>
    </form>
  );
}
