import { Suspense } from "react";
import { listProviders } from "@/lib/dashboard";
import { requireUser } from "../../../guard";
import { saveProviderAction, setProviderEnabledAction } from "../../../actions";
import { ActionForm } from "../../../forms";
import { Badge, Card, CodeBlock, Field, PageHeader, Skeleton, inputCls } from "../../../ui";
import { guarded } from "../../../server";

export const metadata = { title: "Social sign-in" };

const NAMES: Record<string, string> = { google: "Google", github: "GitHub" };

async function Providers({ userId, id }: { userId: string; id: string }) {
  const providers = await guarded(() => listProviders(userId, id));
  return (
    <div className="grid gap-6 lg:grid-cols-2">
      {providers.map((p) => {
        const name = NAMES[p.provider] ?? p.provider;
        return (
          <Card
            key={p.provider}
            title={name}
            description={
              <>
                {p.configured ? (p.enabled ? <Badge tone="good">Enabled</Badge> : <Badge>Disabled</Badge>) : <Badge>Not set up</Badge>}
              </>
            }
          >
            <div className="space-y-4">
              <CodeBlock label={`Redirect URI (paste this into the ${name} developer console)`} value={p.redirectUri} />
              <ActionForm action={saveProviderAction} submit="Save" className="space-y-4">
                <input type="hidden" name="instanceId" value={id} />
                <input type="hidden" name="provider" value={p.provider} />
                <Field label="Client ID">
                  <input name="clientId" required defaultValue={p.clientId ?? ""} autoComplete="off" spellCheck={false} className={`${inputCls} font-mono`} />
                </Field>
                <Field label="Client secret" hint="Encrypted when saved and never shown again, so enter it each time you save.">
                  <input name="clientSecret" type="password" required autoComplete="off" spellCheck={false} className={`${inputCls} font-mono`} />
                </Field>
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" name="enabled" defaultChecked={p.enabled} className="size-4 accent-ink" />
                  Enable {name} sign-in
                </label>
              </ActionForm>
              {p.configured && (
                <ActionForm action={setProviderEnabledAction} submit={p.enabled ? `Disable ${name}` : `Enable ${name}`} tone="ghost" className="space-y-2">
                  <input type="hidden" name="instanceId" value={id} />
                  <input type="hidden" name="provider" value={p.provider} />
                  <input type="hidden" name="enabled" value={p.enabled ? "false" : "true"} />
                </ActionForm>
              )}
            </div>
          </Card>
        );
      })}
    </div>
  );
}

export default async function SocialPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/social`);
  return (
    <div className="space-y-6">
      <PageHeader title="Social sign-in" description="Let people sign in with an existing Google or GitHub account. Create an OAuth app with the provider, then paste its details here." />
      <Suspense fallback={<Skeleton lines={5} />}>
        <Providers userId={userId} id={id} />
      </Suspense>
    </div>
  );
}
