import { requireUser } from "../../../guard";
import { updateSessionSettingsAction } from "../../../actions";
import { ActionForm } from "../../../forms";
import { Card, Field, PageHeader, PlanBadge, Toggle } from "../../../ui";
import { inputCls } from "../../../styles";
import { details } from "../../../server";
import { planNeeded } from "@/lib/plans";
import { sessionSettings } from "@/lib/session-settings";

export const metadata = { title: "Sessions" };

export default async function SessionsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/sessions`);
  const inst = await details(userId, id);
  const s = sessionSettings(inst);
  const need = await planNeeded("session_customization");
  return (
    <div className="space-y-6">
      <PageHeader title="Sessions" description="How long people stay signed in, when idle sessions end, and extra claims in the session token." />
      {need && <p className="text-sm text-stone-600">Inactivity timeout and custom claims need the <PlanBadge plan={need.name} /> plan. <a className="underline" href="/dashboard/billing">Billing</a></p>}
      <Card>
        <ActionForm action={updateSessionSettingsAction} submit="Save session settings" className="max-w-xl space-y-5">
          <input type="hidden" name="instanceId" value={inst.id} />
          <Toggle name="maxLifetimeEnabled" defaultChecked={s.maxLifetimeEnabled} label="Maximum lifetime" description={`Sessions end after ${inst.settings.sessionLifetimeDays} days (set under Sign-in & security). When off, they last up to 90 days.`} />
          <Field label="Inactivity timeout (minutes)" hint="End a session after this many idle minutes. Blank = never.">
            <input name="inactivityTimeoutMinutes" inputMode="numeric" defaultValue={s.inactivityTimeoutMinutes ?? ""} placeholder="Never" className={inputCls} />
          </Field>
          <Toggle name="multiSession" defaultChecked={s.multiSession} label="Multi-session" description="When off, signing in ends the user's other sessions." />
          <Field label="Token lifetime (seconds)" hint="30 to 600.">
            <input name="tokenTtlSeconds" inputMode="numeric" defaultValue={inst.settings.tokenTtlSeconds} className={inputCls} />
          </Field>
          <Field label="Custom claims (JSON)" hint={'Name to template, e.g. {"email": "{{user.email}}"}. Variables: user.id, user.email, user.first_name, user.last_name, org.id, org.role. Reserved names (sub, iss, exp, sid...) are refused.'}>
            <textarea name="customClaims" rows={6} defaultValue={Object.keys(s.customClaims).length ? JSON.stringify(s.customClaims, null, 2) : ""} className={`${inputCls} font-mono`} />
          </Field>
        </ActionForm>
      </Card>
    </div>
  );
}
