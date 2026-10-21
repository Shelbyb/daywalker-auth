import { requireUser } from "../../../guard";
import { updateSettingsAction } from "../../../actions";
import { ActionForm } from "../../../forms";
import { Card, Field, PageHeader, inputCls } from "../../../ui";
import { details } from "../../../server";

export const metadata = { title: "Settings" };

export default async function SettingsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/settings`);
  const inst = await details(userId, id);
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
        </ActionForm>
      </Card>
    </div>
  );
}
