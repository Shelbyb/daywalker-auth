"use client";

import { useState } from "react";
import QRCode from "qrcode";
import type { SecurityInfo } from "@daywalker/auth";
import { hostedClient } from "../hosted-client";
import { Card, Field, Button, Notice, Badge, useAction } from "./ui";

type Step = { kind: "idle" } | { kind: "scan"; qr: string; secret: string } | { kind: "codes"; codes: string[] } | { kind: "confirm"; action: "disable" | "rotate" };

export function TwoFactorSection({ pk, security, onChanged }: { pk: string; security: SecurityInfo; onChanged: () => void }) {
  const client = hostedClient(pk);
  const a = useAction();
  const [step, setStep] = useState<Step>({ kind: "idle" });

  return (
    <Card title="Two-step verification" description="Ask for a code from your authenticator app when you sign in.">
      <div className="mb-4 flex items-center gap-2">
        {security.twoFactorEnabled ? <Badge tone="good">On</Badge> : <Badge>Off</Badge>}
        {security.twoFactorEnabled && (
          <span className="text-xs text-stone-500">{security.backupCodesRemaining} backup code{security.backupCodesRemaining === 1 ? "" : "s"} left</span>
        )}
      </div>

      {step.kind === "idle" && !security.twoFactorEnabled && (
        <Button
          disabled={a.busy}
          onClick={() =>
            a.run(async () => {
              const { uri, secret } = await client.startTotpSetup();
              // Rendered locally: the secret never leaves the browser as an image request.
              setStep({ kind: "scan", qr: await QRCode.toDataURL(uri, { margin: 1, width: 200 }), secret });
            })
          }
        >
          Turn on
        </Button>
      )}

      {step.kind === "scan" && (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            const code = new FormData(e.currentTarget).get("code") as string;
            a.run(async () => {
              setStep({ kind: "codes", codes: await client.confirmTotpSetup(code) });
              onChanged();
            });
          }}
        >
          <ol className="list-decimal space-y-1 pl-5 text-sm text-stone-600">
            <li>Open your authenticator app (Google Authenticator, 1Password, Authy…).</li>
            <li>Scan this QR code, or enter the key by hand.</li>
            <li>Type the 6-digit code it shows.</li>
          </ol>
          {/* eslint-disable-next-line @next/next/no-img-element -- data: URL generated in the browser */}
          <img src={step.qr} alt="QR code to add this account to your authenticator app" width={200} height={200} className="rounded-lg border border-stone-200" />
          <p className="text-xs text-stone-500">
            Key: <code className="break-all rounded bg-stone-100 px-1.5 py-0.5 font-mono">{step.secret.match(/.{1,4}/g)?.join(" ")}</code>
          </p>
          <Field label="6-digit code" name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} required />
          {a.error && <Notice tone="error">{a.error}</Notice>}
          <div className="flex gap-2">
            <Button disabled={a.busy}>Confirm</Button>
            <Button type="button" variant="secondary" onClick={() => setStep({ kind: "idle" })}>Cancel</Button>
          </div>
        </form>
      )}

      {step.kind === "codes" && (
        <div className="space-y-4">
          <Notice tone="success">Two-step verification is on.</Notice>
          <p className="text-sm text-stone-600">
            Save these backup codes somewhere safe. Each works once if you lose your phone. <strong>They won&apos;t be shown again.</strong>
          </p>
          <ul className="grid grid-cols-2 gap-2 rounded-lg bg-stone-50 p-4 font-mono text-sm">
            {step.codes.map((c) => <li key={c}>{c}</li>)}
          </ul>
          <div className="flex gap-2">
            <Button variant="secondary" onClick={() => navigator.clipboard.writeText(step.codes.join("\n"))}>Copy codes</Button>
            <Button onClick={() => setStep({ kind: "idle" })}>I&apos;ve saved them</Button>
          </div>
        </div>
      )}

      {step.kind === "idle" && security.twoFactorEnabled && (
        <div className="flex flex-wrap gap-2">
          <Button variant="secondary" onClick={() => setStep({ kind: "confirm", action: "rotate" })}>New backup codes</Button>
          <Button variant="danger" onClick={() => setStep({ kind: "confirm", action: "disable" })}>Turn off</Button>
        </div>
      )}

      {step.kind === "confirm" && (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            const code = new FormData(e.currentTarget).get("code") as string;
            a.run(async () => {
              if (step.action === "disable") {
                await client.disableTwoFactor(code);
                setStep({ kind: "idle" });
                onChanged();
                return "Two-step verification is off.";
              }
              setStep({ kind: "codes", codes: await client.regenerateBackupCodes(code) });
              onChanged();
            });
          }}
        >
          <p className="text-sm text-stone-600">
            {step.action === "disable" ? "To turn off two-step verification" : "To create new backup codes"}, enter a code from your authenticator app or a backup code.
          </p>
          <Field label="Code" name="code" autoComplete="one-time-code" required maxLength={11} />
          {a.error && <Notice tone="error">{a.error}</Notice>}
          <div className="flex gap-2">
            <Button variant={step.action === "disable" ? "danger" : "primary"} disabled={a.busy}>
              {step.action === "disable" ? "Turn off" : "Create new codes"}
            </Button>
            <Button type="button" variant="secondary" onClick={() => setStep({ kind: "idle" })}>Cancel</Button>
          </div>
        </form>
      )}
      {step.kind === "idle" && a.ok && <div className="mt-3"><Notice tone="success">{a.ok}</Notice></div>}
    </Card>
  );
}
