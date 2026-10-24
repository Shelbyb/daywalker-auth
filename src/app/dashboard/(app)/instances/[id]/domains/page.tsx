import { domainsFor } from "@/lib/dashboard";
import { requireUser } from "../../../guard";
import { addSatelliteAction, primaryDomainAction, removeSatelliteAction, verifySatelliteAction } from "../../../actions";
import { ActionForm, ConfirmAction } from "../../../forms";
import { Badge, Card, Field, PageHeader } from "../../../ui";
import { inputCls } from "../../../styles";
import { guarded } from "../../../server";

export const metadata = { title: "Domains" };

export default async function DomainsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/domains`);
  const d = await guarded(() => domainsFor(userId, id));
  return (
    <div className="space-y-6">
      <PageHeader title="Domains" description="Run one app on several domains. The primary domain is your main site; satellite domains share the same sessions through a secure redirect, without third-party cookies." />
      <Card title="Primary domain" description="An origin like https://example.com. It is added to your allowed origins automatically.">
        <ActionForm action={primaryDomainAction} submit="Save" className="max-w-md space-y-3">
          <input type="hidden" name="instanceId" value={id} />
          <Field label="Primary domain" hint="Leave empty to clear."><input name="primaryDomain" defaultValue={d.primaryDomain ?? ""} maxLength={300} className={inputCls} placeholder="https://example.com" /></Field>
        </ActionForm>
      </Card>
      <Card title="Satellite domains" description="Prove you control each one with a DNS TXT record. Verified satellites are allowed origins too, and are the only ones that can sync sessions.">
        {d.satellites.length ? (
          <ul className="mb-4 space-y-3">
            {d.satellites.map((s) => (
              <li key={s.id} className="rounded-lg border border-stone-200 p-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium">{s.origin}</span>
                  <Badge tone={s.verified ? "neutral" : "warn"}>{s.verified ? "verified" : "unverified"}</Badge>
                </div>
                {s.dns && (
                  <p className="mt-2 text-stone-600">Add a <b>{s.dns.type}</b> record named <code className="font-mono text-xs">{s.dns.name}</code> with value <code className="break-all font-mono text-xs">{s.dns.value}</code></p>
                )}
                <div className="mt-2 flex flex-wrap gap-2">
                  {!s.verified && (
                    <ConfirmAction action={verifySatelliteAction} label="Verify" confirmLabel="Check DNS now" tone="primary" prompt="Look for the TXT record?">
                      <input type="hidden" name="instanceId" value={id} /><input type="hidden" name="domainId" value={s.id} />
                    </ConfirmAction>
                  )}
                  <ConfirmAction action={removeSatelliteAction} label="Remove" confirmLabel="Yes, remove" prompt={`Remove ${s.origin}? It stops syncing sessions.`}>
                    <input type="hidden" name="instanceId" value={id} /><input type="hidden" name="domainId" value={s.id} />
                  </ConfirmAction>
                </div>
              </li>
            ))}
          </ul>
        ) : <p className="mb-4 text-sm text-stone-600">No satellite domains.</p>}
        <ActionForm action={addSatelliteAction} submit="Add satellite" resetOnSuccess className="max-w-md space-y-3">
          <input type="hidden" name="instanceId" value={id} />
          <Field label="Domain" hint={d.environment === "development" ? "On a development instance, localhost needs no DNS record." : "Must use https."}>
            <input name="domain" required maxLength={300} className={inputCls} placeholder="example.org" autoComplete="off" />
          </Field>
        </ActionForm>
      </Card>
    </div>
  );
}
