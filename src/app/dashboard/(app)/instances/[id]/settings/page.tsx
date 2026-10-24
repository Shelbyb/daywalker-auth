import { requireUser } from "../../../guard";
import { HelpLink } from "../../../help";
import { protectionFor, signingKeysFor } from "@/lib/dashboard";
import { rotateSigningKeyAction, updateProtectionAction, updateSettingsAction } from "../../../actions";
import { ActionForm, ConfirmAction } from "../../../forms";
import { Card, Field, PageHeader, Toggle } from "../../../ui";
import { inputCls } from "../../../styles";
import { details, fmtDateTime } from "../../../server";

export const metadata = { title: "Settings" };

export default async function SettingsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/settings`);
  const inst = await details(userId, id);
  const keys = await signingKeysFor(userId, id);
  const prot = await protectionFor(userId, id);
  return (
    <div className="space-y-6">
      <PageHeader title="Settings" description="Basic rules for this instance: its name, which websites may use it, and how passwords and sessions behave." />
      <Card>
        <ActionForm action={updateSettingsAction} submit="Save settings" className="max-w-xl space-y-5">
          <input type="hidden" name="instanceId" value={inst.id} />
          <Field label="Instance name">
            <input name="name" required maxLength={60} defaultValue={inst.name} className={inputCls} />
          </Field>
          <Field label="Allowed origins" hint="One per line. Each must be https, or http://localhost for local development (for example https://myapp.com or http://localhost:3000). They're used for CORS and to check redirect URLs after sign-in.">
            <textarea name="allowedOrigins" rows={5} defaultValue={inst.allowedOrigins.join("\n")} spellCheck={false} className={`${inputCls} font-mono`} />
          </Field>
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Minimum password length" hint="Between 8 and 128 characters.">
              <input name="passwordMinLength" type="number" min={8} max={128} required defaultValue={inst.settings.passwordMinLength} className={inputCls} />
            </Field>
            <Field label="Session lifetime (days)" hint="How long people stay signed in. 1 to 90 days.">
              <input name="sessionLifetimeDays" type="number" min={1} max={90} required defaultValue={inst.settings.sessionLifetimeDays} className={inputCls} />
            </Field>
          </div>
          <div className="divide-y divide-stone-200 rounded-lg border border-stone-200 px-4">
            <Toggle name="breachedPasswordCheck" defaultChecked={inst.settings.breachedPasswordCheck !== false} label="Block breached passwords"
              description={<>Reject new passwords found in known data breaches. Only a 5-character piece of the password&apos;s hash is ever sent to check.</>} />
            <Toggle name="emailCodeSignIn" defaultChecked={inst.settings.emailCodeSignIn === true} label="Email sign-in codes and links"
              description="Let people sign in without a password: we email a 6-digit code and a one-time link. Two-factor still applies." />
          </div>
          <div className="rounded-lg border border-stone-200">
            <div className="border-b border-stone-200 px-4 py-3">
              <h3 className="text-sm font-semibold">MFA strategies <HelpLink slug="guides/two-factor" label="Two-factor" /></h3>
              <p className="text-xs text-stone-600">Which multi-factor methods people can use to verify their identity.</p>
            </div>
            <div className="divide-y divide-stone-200 px-4">
              <div>
                <Toggle name="smsSecondFactor" defaultChecked={inst.settings.smsSecondFactor === true} disabled={!inst.smsConfigured}
                  label="SMS verification code" description="Send a one-time sign-in code by text message."
                  note={inst.smsConfigured ? undefined : "Text messages aren't available on this service yet."} />
                <div className="mb-4 ml-12">
                  <Field label="SMS countries (optional)" hint="Country calling codes people may add a phone from, like 1 44 49 (US/Canada, UK, Germany). Leave empty to allow every country. Limiting this also guards against SMS toll fraud. People who already added a phone keep it.">
                    <input name="smsCountries" defaultValue={(inst.settings.smsCountries ?? []).join(" ")} maxLength={1000} placeholder="1 44 49" className={inputCls} />
                  </Field>
                </div>
              </div>
              <Toggle checked disabled label="Authenticator application" description="Time-based codes from an app such as Google Authenticator. Always available." />
              <Toggle checked disabled label="Passkeys and security keys" description="Sign in or verify with a passkey or hardware key. Always available." />
              <Toggle checked disabled label="Backup codes" description="Single-use codes people save in case they lose their device. Created when they turn on two-factor." />
            </div>
          </div>
        </ActionForm>
      </Card>
      <Card>
        <h2 className="text-lg font-semibold">Sign-up protection and two-factor <HelpLink slug="guides/sign-up-protection" label="Sign-up protection" /><HelpLink slug="guides/two-factor" label="Two-factor" /></h2>
        <p className="mt-1 max-w-xl text-sm text-stone-600">Keep bots and throwaway accounts out, and decide whether everyone must use two-step verification.</p>
        <ActionForm action={updateProtectionAction} submit="Save protection" className="mt-4 max-w-xl space-y-5">
          <input type="hidden" name="instanceId" value={inst.id} />
          <Field label="Only allow these email domains (optional)" hint="Spaces or new lines between them. Subdomains count. Leave empty to allow any domain. Applies to new accounts from sign-up and social sign-in, not SSO.">
            <textarea name="allowedDomains" rows={2} defaultValue={prot.allowedDomains.join("\n")} placeholder="mycompany.com" spellCheck={false} className={`${inputCls} font-mono`} />
          </Field>
          <Field label="Block these email domains (optional)">
            <textarea name="blockedDomains" rows={2} defaultValue={prot.blockedDomains.join("\n")} spellCheck={false} className={`${inputCls} font-mono`} />
          </Field>
          <div className="rounded-lg border border-stone-200 px-4">
            <Toggle name="blockDisposableEmails" defaultChecked={prot.blockDisposableEmails} label="Block throwaway email addresses"
              description="Refuse sign-ups from about 120,000 known disposable email providers." />
          </div>
          <div className="grid gap-5 sm:grid-cols-2">
            <Field label="Turnstile site key (optional)" hint="From Cloudflare Turnstile. Adds a human check to sign-up, sign-in, emailing sign-in codes and password reset. Add your app’s domains to the widget. Leave empty to turn it off.">
              <input name="captchaSiteKey" defaultValue={prot.captcha?.siteKey ?? ""} maxLength={200} spellCheck={false} className={`${inputCls} font-mono`} />
            </Field>
            <Field label="Turnstile secret key" hint={prot.captcha?.secretSet ? "Saved (encrypted). Leave empty to keep it." : "Stored encrypted, never shown again."}>
              <input name="captchaSecretKey" type="password" autoComplete="off" maxLength={200} spellCheck={false} className={`${inputCls} font-mono`} />
            </Field>
          </div>
          <div className="rounded-lg border border-stone-200 px-4">
            <Toggle name="requireTwoFactor" defaultChecked={prot.requireTwoFactor} label="Require multi-factor authentication"
              description={<>After the grace period, people without it can still sign in but get no session token until they set it up on their account page. SSO sign-ins are exempt (the identity provider handles MFA).
                {prot.requireTwoFactor && prot.twoFactorGraceUntil && <> Grace period ends {fmtDateTime(prot.twoFactorGraceUntil)}.</>}</>} />
            <div className="mb-4 ml-12">
              <Field label="Grace period (days)" hint="Only used when you turn it on or change it. 0 means right away.">
                <input name="twoFactorGraceDays" type="number" min={0} max={90} placeholder="7" className={inputCls} />
              </Field>
            </div>
          </div>
        </ActionForm>
      </Card>
      <Card>
        <h2 className="text-lg font-semibold">Signing keys <HelpLink slug="guides/rotating-keys" label="Rotating keys" /></h2>
        <p className="mt-1 max-w-xl text-sm text-stone-600">
          These keys sign your users&apos; session tokens. Rotating switches to a new key without signing anyone out: the old key stays published for a day so tokens already issued keep working.
          Rotate on a schedule, or right away if you think a key was exposed.
        </p>
        <ul className="mt-4 space-y-1 text-sm">
          {keys.map((k) => (
            <li key={k.id} className="flex flex-wrap items-center gap-x-3 gap-y-1">
              <code className="font-mono text-xs">{k.id}</code>
              <span className={k.active ? "text-emerald-700" : "text-stone-500"}>{k.active ? "Signing" : `Retired ${fmtDateTime(k.retiredAt)}`}</span>
              <span className="text-stone-500">Created {fmtDateTime(k.createdAt)}</span>
            </li>
          ))}
        </ul>
        <div className="mt-4">
          <ConfirmAction action={rotateSigningKeyAction} label="Rotate signing key" confirmLabel="Yes, rotate" prompt="Start signing with a new key? Nobody is signed out." tone="primary">
            <input type="hidden" name="instanceId" value={inst.id} />
          </ConfirmAction>
        </div>
      </Card>
    </div>
  );
}
