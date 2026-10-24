import { environmentsFor, testModeFor } from "@/lib/dashboard";
import { requireUser } from "../../../guard";
import { addProductionAction, cloneConfigAction, testModeAction } from "../../../actions";
import { ActionForm } from "../../../forms";
import { Badge, Card, PageHeader, Toggle } from "../../../ui";
import { guarded } from "../../../server";

export const metadata = { title: "Environments" };

export default async function EnvironmentsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/environments`);
  const v = await guarded(() => environmentsFor(userId, id));
  const tm = await guarded(() => testModeFor(userId, id));
  const hasProd = v.environments.some((e) => e.environment === "production");
  return (
    <div className="space-y-6">
      <PageHeader title="Environments" description="Development and production are separate instances with their own users, keys and signing keys. Nothing is shared at runtime." />
      <Card title={v.application?.name ?? "This instance"}>
        <ul className="space-y-2 text-sm">
          {v.environments.map((e) => (
            <li key={e.instanceId} className="flex flex-wrap items-center gap-2">
              <Badge tone={e.environment === "production" ? "warn" : "neutral"}>{e.environment}</Badge>
              <a className="underline" href={`/dashboard/instances/${encodeURIComponent(e.instanceId)}`}>{e.name}</a>
              <code className="font-mono text-xs text-stone-600">{e.publishableKey}</code>
              {e.current && <span className="text-xs text-stone-500">(this one)</span>}
            </li>
          ))}
          {!v.environments.length && <li className="text-stone-600">This instance was created before applications existed and has no sibling environments.</li>}
        </ul>
      </Card>
      <Card title="Test mode" description={tm.available ? `For end-to-end tests. Addresses like name${tm.emailTag}@example.com and phone numbers ${tm.phoneRange} accept the code ${tm.code}, and nothing is sent to them. Real addresses and numbers are unaffected.` : "Test mode is only available on development instances."}>
        {tm.available ? (
          <ActionForm action={testModeAction} submit="Save" className="max-w-md space-y-3">
            <input type="hidden" name="instanceId" value={id} />
            <Toggle name="enabled" label="Turn on test mode" description="Don't use it for real people: anyone can sign in to a test address with the public code." defaultChecked={tm.enabled} />
          </ActionForm>
        ) : null}
      </Card>
      {v.environment === "development" && v.application && !hasProd && (
        <Card title="Create the production instance" description="Gets its own publishable and secret keys (sk_live_…). The secret is shown once.">
          <ActionForm action={addProductionAction} submit="Create production instance" secretLabel="Production secret key" showKeys className="space-y-4">
            <input type="hidden" name="instanceId" value={id} />
          </ActionForm>
        </Card>
      )}
      {v.environment === "production" && v.environments.some((e) => e.environment === "development") && (
        <Card title="Copy configuration from development" description="Copies settings, never users. Social provider and webhook secrets are copied only if you tick them, and are re-encrypted for production. Webhook endpoints are created disabled.">
          <ActionForm action={cloneConfigAction} submit="Copy configuration" secretLabel="New webhook signing secrets (shown once)" className="max-w-xl space-y-3">
            <input type="hidden" name="instanceId" value={id} />
            <Toggle name="settings" label="Settings" description="Sign-in options, sessions, organizations, branding, legal" defaultChecked />
            <Toggle name="providers" label="Social providers" description="Without secrets they are created disabled until you add a production secret" defaultChecked />
            <Toggle name="templates" label="Email templates" defaultChecked />
            <Toggle name="roles" label="Organization roles" description="Merged by key; production-only roles are kept" defaultChecked />
            <Toggle name="webhooks" label="Webhook endpoints" description="Created disabled" />
            <Toggle name="origins" label="Allowed origins" description="Localhost origins are never copied" />
            <Toggle name="secrets_providers" label="Also copy social provider secrets" description="Only if the same OAuth apps serve both environments" />
            <Toggle name="secrets_webhooks" label="Also copy webhook signing secrets" />
          </ActionForm>
        </Card>
      )}
    </div>
  );
}
