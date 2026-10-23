"use client";

import { useEffect, useState } from "react";
import QRCode from "qrcode";
import type { SecurityInfo } from "@daywalker/auth";
import { hostedClient } from "../hosted-client";
import { Card, Field, Button, Notice, Badge, useAction } from "./ui";

type Action = "disable" | "rotate" | "remove-phone" | "add-app" | "add-phone" | "add-key" | "remove-key";
type Step =
  | { kind: "idle" }
  | { kind: "scan"; qr: string; secret: string }
  | { kind: "phone"; currentCode?: string }
  | { kind: "phone-code"; phone: string }
  | { kind: "key-name"; currentCode?: string }
  | { kind: "codes"; codes: string[] }
  | { kind: "confirm"; action: Action; keyId?: string };

const PROMPT: Record<Action, string> = {
  disable: "To turn off two-step verification",
  rotate: "To create new backup codes",
  "remove-phone": "To remove your phone",
  "add-app": "To add an authenticator app",
  "add-phone": "To add a phone",
  "add-key": "To add a security key",
  "remove-key": "To remove this security key",
};
const MAX_KEYS = 5;

export function TwoFactorSection({ pk, security, onChanged }: { pk: string; security: SecurityInfo; onChanged: () => void }) {
  const client = hostedClient(pk);
  const a = useAction();
  const [step, setStep] = useState<Step>({ kind: "idle" });
  const [texted, setTexted] = useState<string | null>(null);
  const on = security.twoFactorEnabled;
  const canAddPhone = security.smsAvailable && !security.smsPhone;
  const keys = security.securityKeys ?? [];
  const [webauthn, setWebauthn] = useState(false); // only known in the browser
  useEffect(() => setWebauthn(client.passkeysSupported()), [client]);
  const canAddKey = webauthn && keys.length < MAX_KEYS;

  const startApp = (currentCode?: string) =>
    a.run(async () => {
      const { uri, secret } = await client.startTotpSetup(currentCode);
      // Rendered locally: the secret never leaves the browser as an image request.
      setStep({ kind: "scan", qr: await QRCode.toDataURL(uri, { margin: 1, width: 200 }), secret });
    });
  const done = (codes: string[], message: string) => {
    onChanged();
    if (codes.length) setStep({ kind: "codes", codes });
    else {
      setStep({ kind: "idle" });
      return message;
    }
  };

  return (
    <Card title="Two-step verification" description="Ask for a second step when you sign in: a code from an authenticator app, a text message, or a security key.">
      <div className="mb-4 flex flex-wrap items-center gap-2">
        {on ? <Badge tone="good">On</Badge> : <Badge>Off</Badge>}
        {security.totpEnabled && <Badge>Authenticator app</Badge>}
        {security.smsPhone && <Badge>Text message to {security.smsPhone}</Badge>}
        {keys.length > 0 && <Badge>{keys.length} security key{keys.length === 1 ? "" : "s"}</Badge>}
        {on && <span className="text-xs text-stone-500">{security.backupCodesRemaining} backup code{security.backupCodesRemaining === 1 ? "" : "s"} left</span>}
      </div>

      {step.kind === "idle" && (
        <div className="flex flex-wrap gap-2">
          {!security.totpEnabled && (
            <Button disabled={a.busy} onClick={() => (on ? setStep({ kind: "confirm", action: "add-app" }) : startApp())}>
              {on ? "Add an authenticator app" : "Use an authenticator app"}
            </Button>
          )}
          {canAddPhone && (
            <Button variant={on || !security.totpEnabled ? "secondary" : "primary"} onClick={() => (on ? setStep({ kind: "confirm", action: "add-phone" }) : setStep({ kind: "phone" }))}>
              {on ? "Add a phone" : "Use text messages"}
            </Button>
          )}
          {canAddKey && (
            <Button variant="secondary" onClick={() => (on ? setStep({ kind: "confirm", action: "add-key" }) : setStep({ kind: "key-name" }))}>
              Add a security key
            </Button>
          )}
          {security.smsPhone && <Button variant="secondary" onClick={() => setStep({ kind: "confirm", action: "remove-phone" })}>Remove phone</Button>}
          {on && <Button variant="secondary" onClick={() => setStep({ kind: "confirm", action: "rotate" })}>New backup codes</Button>}
          {on && <Button variant="danger" onClick={() => setStep({ kind: "confirm", action: "disable" })}>Turn off</Button>}
        </div>
      )}

      {step.kind === "idle" && keys.length > 0 && (
        <ul className="mt-4 divide-y divide-stone-100 rounded-lg border border-stone-200 text-sm">
          {keys.map((k) => (
            <li key={k.id} className="flex items-center justify-between gap-3 px-3 py-2">
              <span>
                <span className="font-medium">{k.name}</span>
                <span className="ml-2 text-xs text-stone-500">{k.lastUsedAt ? `Used ${new Date(k.lastUsedAt).toLocaleDateString()}` : "Never used"}</span>
              </span>
              <Button variant="secondary" onClick={() => setStep({ kind: "confirm", action: "remove-key", keyId: k.id })}>Remove</Button>
            </li>
          ))}
        </ul>
      )}

      {step.kind === "key-name" && (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            const name = String(new FormData(e.currentTarget).get("name") ?? "");
            a.run(async () => {
              const r = await client.addSecurityKey({ name, currentCode: step.currentCode });
              return done(r.backupCodes, "Security key added.");
            });
          }}
        >
          <p className="text-sm text-stone-600">Give the key a name you&apos;ll recognise, then press Continue and touch the key when your browser asks.</p>
          <Field label="Name" name="name" placeholder="YubiKey on my keychain" maxLength={60} />
          {a.error && <Notice tone="error">{a.error}</Notice>}
          <div className="flex gap-2">
            <Button disabled={a.busy}>Continue</Button>
            <Button type="button" variant="secondary" onClick={() => setStep({ kind: "idle" })}>Cancel</Button>
          </div>
        </form>
      )}

      {step.kind === "scan" && (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            const code = new FormData(e.currentTarget).get("code") as string;
            a.run(async () => done(await client.confirmTotpSetup(code), "Authenticator app added."));
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

      {step.kind === "phone" && (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            const phone = String(new FormData(e.currentTarget).get("phone") ?? "");
            a.run(async () => {
              const r = await client.startSmsSetup(phone, step.currentCode);
              setStep({ kind: "phone-code", phone: r.phone });
            });
          }}
        >
          <p className="text-sm text-stone-600">We&apos;ll text a code to this number now, and each time you sign in. Text messages are less secure than an authenticator app, so use an app if you can.</p>
          <Field label="Mobile number (international format)" name="phone" type="tel" autoComplete="tel" placeholder="+1 415 555 0100" required maxLength={32} />
          {a.error && <Notice tone="error">{a.error}</Notice>}
          <div className="flex gap-2">
            <Button disabled={a.busy}>Text me a code</Button>
            <Button type="button" variant="secondary" onClick={() => setStep({ kind: "idle" })}>Cancel</Button>
          </div>
        </form>
      )}

      {step.kind === "phone-code" && (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            const code = new FormData(e.currentTarget).get("code") as string;
            a.run(async () => done(await client.confirmSmsSetup(code), "Phone added."));
          }}
        >
          <p className="text-sm text-stone-600">Enter the code we texted to {step.phone}.</p>
          <Field label="Code" name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={10} required />
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

      {step.kind === "confirm" && (
        <form
          className="space-y-4"
          onSubmit={(e) => {
            e.preventDefault();
            const code = String(new FormData(e.currentTarget).get("code") ?? "");
            const action = step.action;
            a.run(async () => {
              if (action === "add-app") return void startApp(code);
              if (action === "add-phone") return void setStep({ kind: "phone", currentCode: code });
              if (action === "add-key") return void setStep({ kind: "key-name", currentCode: code });
              if (action === "remove-key") {
                await client.removeSecurityKey(step.keyId ?? "", code);
                return done([], "Security key removed.");
              }
              if (action === "disable") {
                await client.disableTwoFactor(code);
                return done([], "Two-step verification is off.");
              }
              if (action === "remove-phone") {
                await client.removeSmsPhone(code);
                return done([], "Phone removed.");
              }
              setStep({ kind: "codes", codes: await client.regenerateBackupCodes(code) });
              onChanged();
            });
          }}
        >
          <p className="text-sm text-stone-600">
            {PROMPT[step.action]}, enter {[security.totpEnabled && "a code from your authenticator app", security.smsPhone && "a texted code", "a backup code"].filter(Boolean).join(", ").replace(/, ([^,]*)$/, " or $1")}.
          </p>
          <Field label="Code" name="code" autoComplete="one-time-code" required maxLength={11} />
          {security.smsPhone && (
            <button
              type="button"
              className="text-sm text-stone-500 underline underline-offset-4 hover:text-ink"
              onClick={() => a.run(async () => setTexted((await client.sendSmsCode()).phone))}
            >
              {texted ? `Code sent to ${texted}. Send another` : `Text a code to ${security.smsPhone}`}
            </button>
          )}
          {a.error && <Notice tone="error">{a.error}</Notice>}
          <div className="flex gap-2">
            <Button variant={step.action === "disable" || step.action === "remove-phone" || step.action === "remove-key" ? "danger" : "primary"} disabled={a.busy}>Continue</Button>
            <Button type="button" variant="secondary" onClick={() => { setStep({ kind: "idle" }); setTexted(null); }}>Cancel</Button>
          </div>
        </form>
      )}
      {step.kind === "idle" && a.ok && <div className="mt-3"><Notice tone="success">{a.ok}</Notice></div>}
    </Card>
  );
}
