"use client";

import { useEffect, useState } from "react";
import type { ReauthRequirements } from "@daywalker/auth";
import { hostedClient } from "../hosted-client";
import { Card, Field, Button, Notice, useAction } from "./ui";

type Mode = "export" | "delete" | null;

/** Download your data, or delete the account. Both ask you to prove who you are again. */
export function DataSection({ pk, back }: { pk: string; back: string | null }) {
  const client = hostedClient(pk);
  const a = useAction();
  const [mode, setMode] = useState<Mode>(null);
  const [need, setNeed] = useState<ReauthRequirements | null>(null);
  const [sent, setSent] = useState(false);

  useEffect(() => {
    if (!mode) return;
    setNeed(null);
    setSent(false);
    client.getReauthRequirements().then(setNeed, () => {});
  }, [mode]); // eslint-disable-line react-hooks/exhaustive-deps

  function submit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const reauth = {
      password: (f.get("password") as string) || undefined,
      code: (f.get("code") as string) || undefined,
      emailCode: (f.get("emailCode") as string) || undefined,
    };
    a.run(async () => {
      if (mode === "export") {
        const data = await client.exportData(reauth);
        const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
        const link = document.createElement("a");
        link.href = url;
        link.download = "my-data.json";
        link.click();
        URL.revokeObjectURL(url);
        setMode(null);
        return "Your data was downloaded.";
      }
      const r = await client.deleteAccount(reauth);
      window.location.assign(back ?? `/sign-in?pk=${encodeURIComponent(pk)}`);
      return r.deleted ? "Account deleted." : `Account scheduled for deletion on ${r.scheduledFor.slice(0, 10)}.`;
    });
  }

  return (
    <Card title="Your data" description="Download everything we hold about you, or delete your account.">
      {!mode ? (
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" onClick={() => { a.run(async () => ""); setMode("export"); }}>Download my data</Button>
          <Button variant="danger" onClick={() => { a.run(async () => ""); setMode("delete"); }}>Delete account</Button>
        </div>
      ) : (
        <form className="space-y-4" onSubmit={submit}>
          {mode === "delete" && (
            <p className="text-sm text-stone-500">You will be signed out everywhere. Your account is deleted after a waiting period, and an email link lets you cancel until then.</p>
          )}
          {!need && <p className="text-sm text-stone-500">Loading…</p>}
          {need?.password && <Field label="Password" name="password" type="password" autoComplete="current-password" required maxLength={256} />}
          {need?.twoFactor && <Field label="Two-factor or backup code" name="code" autoComplete="one-time-code" maxLength={64} />}
          {need?.emailCode && (
            <>
              <Button type="button" variant="secondary" disabled={a.busy} onClick={() => a.run(async () => { await client.sendReauthCode(); setSent(true); return "We emailed you a code."; })}>
                {sent ? "Send again" : "Email me a code"}
              </Button>
              <Field label="Code from your email" name="emailCode" inputMode="numeric" autoComplete="one-time-code" maxLength={10} required />
            </>
          )}
          {a.error && <Notice tone="error">{a.error}</Notice>}
          {a.ok && <Notice tone="success">{a.ok}</Notice>}
          <div className="flex gap-2">
            <Button variant={mode === "delete" ? "danger" : "primary"} disabled={a.busy || !need}>{mode === "delete" ? "Delete my account" : "Download"}</Button>
            <Button type="button" variant="secondary" onClick={() => setMode(null)}>Cancel</Button>
          </div>
        </form>
      )}
      {!mode && a.ok && <div className="mt-3"><Notice tone="success">{a.ok}</Notice></div>}
    </Card>
  );
}
