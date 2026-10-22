"use client";

import { useEffect, useState } from "react";
import { AuthError } from "@daywalker/auth";
import { hostedClient } from "./hosted-client";
import { Submit, Alert } from "./code-input";

/** Second step of sign-in: authenticator code, or a backup code if the device is lost. */
export function SecondFactorStep({ pk, onDone }: { pk: string; onDone: (name: string) => void }) {
  const [useBackup, setUseBackup] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [smsPhone, setSmsPhone] = useState<string | null>(null);
  const [texted, setTexted] = useState(false);
  const [onlySms, setOnlySms] = useState(false);
  useEffect(() => {
    hostedClient(pk)
      .getSecondFactorOptions()
      .then((o) => {
        setSmsPhone(o.sms);
        setOnlySms(!o.totp && !!o.sms);
      })
      .catch(() => {});
  }, [pk]);

  async function text() {
    setError(null);
    try {
      await hostedClient(pk).sendSecondFactorSms();
      setTexted(true);
      setUseBackup(false);
    } catch (err) {
      setError(err instanceof AuthError ? err.message : "Network error. Try again.");
    }
  }

  async function onSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { user } = await hostedClient(pk).completeSecondFactor(String(new FormData(e.currentTarget).get("code") ?? ""), !useBackup && texted ? "sms" : undefined);
      onDone(user.firstName || user.emailAddresses[0]?.email || "");
    } catch (err) {
      setError(err instanceof AuthError ? err.message : "Network error. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="space-y-4">
      <h2 className="text-lg font-semibold">Two-step verification</h2>
      <p className="text-sm text-stone-500">
        {useBackup
          ? "Enter one of your backup codes. Each code works once."
          : texted
            ? `Enter the code we texted to ${smsPhone}.`
            : onlySms
              ? `We'll text a code to ${smsPhone}.`
              : "Enter the 6-digit code from your authenticator app."}
      </p>
      <label className="block">
        <span className="sr-only">{useBackup ? "Backup code" : "Authentication code"}</span>
        <input
          key={useBackup ? "backup" : "totp"}
          name="code"
          required
          autoFocus
          autoComplete="one-time-code"
          inputMode={useBackup ? "text" : "numeric"}
          maxLength={useBackup ? 11 : 6}
          placeholder={useBackup ? "xxxxx-xxxxx" : "123456"}
          className="w-full rounded-lg border border-stone-300 bg-white px-3 py-2 text-center font-mono text-lg tracking-[0.3em] outline-none focus:border-dawn focus:ring-2 focus:ring-dawn/30"
        />
      </label>
      {error && <Alert>{error}</Alert>}
      <Submit busy={busy}>Verify</Submit>
      {smsPhone && !useBackup && (
        <button type="button" onClick={() => void text()} className="w-full text-center text-sm text-stone-500 hover:text-ink">
          {texted ? "Send another code" : `Text a code to ${smsPhone}`}
        </button>
      )}
      <button type="button" onClick={() => { setUseBackup((b) => !b); setError(null); }} className="w-full text-center text-sm text-stone-500 hover:text-ink">
        {useBackup ? "Use your authenticator app instead" : "Lost your device? Use a backup code"}
      </button>
    </form>
  );
}
