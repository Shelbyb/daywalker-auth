import { apiKeysFor, m2mFor } from "@/lib/dashboard";
import { requireUser } from "../../../guard";
import { apiKeySettingsAction, createM2mAction, deleteM2mAction, revokeUserApiKeyAction, rotateM2mAction } from "../../../actions";
import { ActionForm, ConfirmAction } from "../../../forms";
import { Card, EmptyState, Field, PageHeader, Toggle } from "../../../ui";
import { inputCls } from "../../../styles";
import { fmtDate, guarded } from "../../../server";

export const metadata = { title: "Machine and API keys" };

export default async function MachinePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/machine`);
  const [clients, ak] = await Promise.all([guarded(() => m2mFor(userId, id)), guarded(() => apiKeysFor(userId, id))]);
  return (
    <div className="space-y-6">
      <PageHeader title="Machine and API keys" description="Let your services get short-lived tokens (client credentials), and let your users and organizations hold API keys for your own API." />
      <Card title="Machine clients" description="A client exchanges its ID and secret at /v1/m2m/token for a short-lived JWT your services verify with verifyMachineToken. Secrets are shown once.">
        {clients.length ? (
          <div className="overflow-x-auto rounded-xl border border-stone-200 bg-white">
            <table className="w-full min-w-[40rem] text-left text-sm">
              <thead className="border-b border-stone-200 text-xs uppercase text-stone-500"><tr><th className="p-3">Name</th><th className="p-3">Client ID</th><th className="p-3">Scopes</th><th className="p-3">Last used</th><th className="p-3"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {clients.map((c) => (
                  <tr key={c.id} className="border-b border-stone-100 align-top last:border-0">
                    <td className="p-3 font-medium">{c.name}</td>
                    <td className="p-3 font-mono text-xs">{c.id}<div className="text-stone-500">secret {c.secretPrefix}…{c.rotating ? " (rotating)" : ""}</div></td>
                    <td className="p-3 text-xs">{c.scopes.join(" ") || "none"}</td>
                    <td className="p-3 text-stone-600">{fmtDate(c.lastUsedAt)}</td>
                    <td className="space-y-2 p-3">
                      <ConfirmAction action={rotateM2mAction} label="Rotate secret" confirmLabel="Yes, rotate" tone="primary" prompt="Create a new secret? The old one stops working immediately." secretLabel="New client secret">
                        <input type="hidden" name="instanceId" value={id} /><input type="hidden" name="clientId" value={c.id} />
                      </ConfirmAction>
                      <ConfirmAction action={deleteM2mAction} label="Delete" confirmLabel="Yes, delete" prompt={`Delete "${c.name}"? Tokens already issued work until they expire.`}>
                        <input type="hidden" name="instanceId" value={id} /><input type="hidden" name="clientId" value={c.id} />
                      </ConfirmAction>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : <EmptyState title="No machine clients">Create one below.</EmptyState>}
        <div className="mt-4">
          <ActionForm action={createM2mAction} submit="Create client" resetOnSuccess secretLabel="Client secret" className="max-w-md space-y-4">
            <input type="hidden" name="instanceId" value={id} />
            <Field label="Name"><input name="name" required maxLength={60} autoComplete="off" className={inputCls} /></Field>
            <Field label="Scopes" hint="Space separated, like read:invoices write:invoices">
              <input name="scopes" maxLength={1000} autoComplete="off" className={inputCls} />
            </Field>
            <Field label="Token lifetime (seconds)" hint="30 to 3600. Default 300."><input name="ttl" inputMode="numeric" maxLength={4} className={inputCls} /></Field>
          </ActionForm>
        </div>
      </Card>
      <Card title="User and organization API keys" description="Keys your users create for your API. Off by default. Self-service keys can only use the scopes you allow here.">
        <ActionForm action={apiKeySettingsAction} submit="Save" className="max-w-md space-y-3">
          <input type="hidden" name="instanceId" value={id} />
          <Toggle name="enabled" label="Let users and organizations create API keys" defaultChecked={ak.settings.enabled} />
          <Field label="Allowed scopes"><input name="allowedScopes" defaultValue={ak.settings.allowedScopes.join(" ")} className={inputCls} /></Field>
          <Field label="Max active keys per user or organization"><input name="maxPerSubject" defaultValue={ak.settings.maxPerSubject} inputMode="numeric" className={inputCls} /></Field>
          <Field label="Require keys to expire within (days)" hint="Leave empty for no limit."><input name="maxExpiryDays" defaultValue={ak.settings.maxExpiryDays ?? ""} inputMode="numeric" className={inputCls} /></Field>
        </ActionForm>
        <div className="mt-4 overflow-x-auto rounded-xl border border-stone-200 bg-white">
          {ak.keys.length ? (
            <table className="w-full min-w-[40rem] text-left text-sm">
              <thead className="border-b border-stone-200 text-xs uppercase text-stone-500"><tr><th className="p-3">Name</th><th className="p-3">Key</th><th className="p-3">Owner</th><th className="p-3">Last used</th><th className="p-3"><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {ak.keys.map((k) => (
                  <tr key={k.id} className="border-b border-stone-100 last:border-0">
                    <td className="p-3 font-medium">{k.name}</td>
                    <td className="p-3 font-mono text-xs">{k.prefix}…</td>
                    <td className="p-3 font-mono text-xs">{k.subject.type} {k.subject.id}</td>
                    <td className="p-3 text-stone-600">{fmtDate(k.lastUsedAt)}</td>
                    <td className="p-3">
                      <ConfirmAction action={revokeUserApiKeyAction} label="Revoke" confirmLabel="Yes, revoke" prompt={`Revoke "${k.name}"?`}>
                        <input type="hidden" name="instanceId" value={id} /><input type="hidden" name="keyId" value={k.id} />
                      </ConfirmAction>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : <p className="p-4 text-sm text-stone-600">No active keys.</p>}
        </div>
      </Card>
    </div>
  );
}
