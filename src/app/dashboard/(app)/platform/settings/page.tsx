import { platformSettingsView } from "@/lib/platform-settings";
import { requirePlatformPage } from "../../guard";
import { ActionForm } from "../../forms";
import { Badge, Card, Field, PageHeader } from "../../ui";
import { inputCls } from "../../styles";
import { fmtDateTime } from "../../server";
import { platformSettingsAction } from "../actions";

export const metadata = { title: "Platform settings" };

const source = (s: "saved" | "env" | "unset") =>
  s === "saved" ? <Badge tone="good">saved here</Badge> : s === "env" ? <Badge>from environment</Badge> : <Badge tone="bad">not set</Badge>;

export default async function PlatformSettingsPage() {
  await requirePlatformPage("/dashboard/platform/settings", "admin");
  const s = await platformSettingsView();
  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform settings"
        description="Providers every instance uses. Values saved here override the server environment; leave a field empty to fall back to it. Secrets are encrypted and never shown again. Changes are recorded in the platform audit log."
      />
      <ActionForm action={platformSettingsAction} submit="Save platform settings" className="space-y-6">
        <Card title="Email (Resend)" description={<>Transport: <code className="font-mono">{s.mailTransport}</code>{s.mailTransport === "dev" ? " (emails are logged, not sent: set MAIL_TRANSPORT=resend on the server to send)" : ""}.</>}>
          <div className="space-y-4">
            <Field label="From address" hint={`Empty uses the default: ${s.mailFromDefault}`}>
              <input name="mailFrom" defaultValue={s.mailFrom} maxLength={200} placeholder={s.mailFromDefault} autoComplete="off" className={inputCls} />
            </Field>
            <Field label="Resend API key" hint={<>Currently {source(s.resendApiKey)}. Empty keeps the current key.</>}>
              <input name="resendApiKey" type="password" maxLength={200} placeholder="re_…" autoComplete="off" className={inputCls} />
            </Field>
            {s.resendApiKey === "saved" && (
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="clearResendApiKey" className="size-4 accent-ink" /> Remove the saved key (fall back to the environment)</label>
            )}
          </div>
        </Card>
        <Card title="SMS (Twilio Verify)" description="Used for SMS two-factor in every instance that turns it on. SMS is unavailable until the account SID, auth token and Verify service SID are all set.">
          <div className="space-y-4">
            <Field label="Account SID" hint={s.twilioFromEnv && !s.twilioAccountSid ? "Empty: using the environment's value." : undefined}>
              <input name="twilioAccountSid" defaultValue={s.twilioAccountSid} maxLength={34} placeholder="AC…" autoComplete="off" className={`${inputCls} font-mono`} />
            </Field>
            <Field label="Auth token" hint={<>Currently {source(s.twilioAuthToken)}. Empty keeps the current token.</>}>
              <input name="twilioAuthToken" type="password" maxLength={200} autoComplete="off" className={inputCls} />
            </Field>
            {s.twilioAuthToken === "saved" && (
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="clearTwilioAuthToken" className="size-4 accent-ink" /> Remove the saved token (fall back to the environment)</label>
            )}
            <Field label="Verify service SID">
              <input name="twilioVerifyServiceSid" defaultValue={s.twilioVerifyServiceSid} maxLength={34} placeholder="VA…" autoComplete="off" className={`${inputCls} font-mono`} />
            </Field>
          </div>
        </Card>
        {s.updatedAt && <p className="text-xs text-stone-500">Last saved {fmtDateTime(s.updatedAt)}.</p>}
      </ActionForm>
    </div>
  );
}
