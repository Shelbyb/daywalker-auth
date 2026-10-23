import Link from "next/link";
import { ssoFor } from "@/lib/dashboard";
import { requireUser } from "../../../guard";
import { createScimTokenAction, setScimAdminGroupsAction, singleLogoutAction, createSsoAction, deleteSsoAction, requireSsoAction, revokeScimTokenAction, toggleSsoAction } from "../../../actions";
import { ActionForm, ConfirmAction } from "../../../forms";
import { Badge, Card, CodeBlock, EmptyState, Field, PageHeader } from "../../../ui";
import { inputCls } from "../../../styles";
import { guarded } from "../../../server";

export const metadata = { title: "SSO" };

export default async function SsoPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/sso`);
  const { connections, orgs } = await guarded(() => ssoFor(userId, id));
  const orgName = (oid: string | null) => orgs.find((o) => o.id === oid)?.name;
  return (
    <div className="space-y-6">
      <PageHeader
        title="Enterprise SSO (SAML)"
        description={<>Let a company&apos;s people sign in with their own identity provider, such as Okta, Microsoft Entra ID or Google Workspace. Anyone with an email at the connection&apos;s domains signs in through it. See the <Link href="/docs/guides/enterprise-sso" className="font-medium underline decoration-dawn decoration-2 underline-offset-4">guide</Link>.</>}
      />
      {connections.length === 0 && <EmptyState title="No SSO connections yet">Add one below for each company that wants single sign-on.</EmptyState>}
      {connections.map((c) => (
        <Card key={c.id} title={c.name} description={<>{c.enabled ? <Badge tone="good">Enabled</Badge> : <Badge>Disabled</Badge>}{c.ssoRequired && <> <Badge tone="good">SSO required</Badge></>} <span className="ml-2 text-stone-600">{c.domains.join(", ")}</span>{c.organizationId && <span className="ml-2 text-stone-600">→ joins {orgName(c.organizationId) ?? "an organization"}</span>}</>}>
          <div className="space-y-3">
            <p className="text-sm text-stone-600">Give these to the identity provider:</p>
            <CodeBlock label="ACS (reply) URL" value={c.acsUrl} />
            <CodeBlock label="Entity ID / Audience" value={c.spEntityId} />
            <CodeBlock label="Single logout URL" value={c.spSloUrl} />
            <p className="text-xs text-stone-500">
              Or upload the metadata from <span className="font-mono">{c.spEntityId}</span>. The NameID or an <span className="font-mono">email</span> attribute must carry the user&apos;s email, and assertions must be signed.
            </p>
            <div className="text-xs text-stone-500">
              Signing certificate{c.certificates.length > 1 ? "s" : ""}: {c.certificates.map((x) => <span key={x.fingerprint256} className="mr-3 inline-block">{x.subject.split("\n").find((l) => l.startsWith("CN=")) ?? "certificate"} · expires {new Date(x.validTo).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" })}</span>)}
            </div>
            <div className="space-y-2 rounded-lg border border-stone-200 p-3">
              <p className="text-sm font-medium">
                Single logout {c.singleLogout ? <Badge tone="good">On</Badge> : <Badge>Off</Badge>}
              </p>
              <p className="text-xs text-stone-500">
                When the identity provider signs someone out, their sessions here end too (always on, once it knows the URL above). Turn the switch on to also sign people out at the identity provider when they sign out of your app.
              </p>
              <ActionForm action={singleLogoutAction} submit="Save logout settings" tone="ghost" className="space-y-2">
                <input type="hidden" name="instanceId" value={id} />
                <input type="hidden" name="connectionId" value={c.id} />
                <Field label="Identity provider logout URL" hint="From its metadata, or its admin console (HTTP-Redirect).">
                  <input name="sloUrl" type="url" defaultValue={c.sloUrl ?? ""} placeholder="https://" className={`${inputCls} font-mono`} />
                </Field>
                <label className="flex items-center gap-2 text-sm">
                  <input type="checkbox" name="singleLogout" defaultChecked={c.singleLogout} /> Sign out at the identity provider too
                </label>
              </ActionForm>
            </div>
            <div className="space-y-2 rounded-lg border border-stone-200 p-3">
              <p className="text-sm font-medium">
                User provisioning (SCIM) {c.scim.enabled ? <Badge tone="good">On</Badge> : <Badge>Off</Badge>}
              </p>
              <p className="text-xs text-stone-500">
                Let the identity provider create, update and deactivate people here automatically. Give it this base URL and a token. See the <Link href="/docs/guides/enterprise-sso#automatic-provisioning-scim" className="font-medium underline decoration-dawn decoration-2 underline-offset-4">guide</Link>.
              </p>
              {c.scim.enabled && <CodeBlock label="SCIM base URL" value={c.scim.baseUrl} />}
              {c.scim.enabled && c.scim.tokenPrefix && <p className="text-xs text-stone-500">Current token starts with <span className="font-mono">{c.scim.tokenPrefix}…</span></p>}
              {c.scim.enabled && c.organizationId && (
                <ActionForm action={setScimAdminGroupsAction} submit="Save admin groups" tone="ghost" className="space-y-2">
                  <input type="hidden" name="instanceId" value={id} />
                  <input type="hidden" name="connectionId" value={c.id} />
                  <Field label="Admin groups (optional)" hint="Names of groups pushed by the identity provider, one per line. Their members become admins of the organization; everyone else stays a member. Leave empty to manage roles here.">
                    <textarea name="groups" rows={2} defaultValue={c.scim.adminGroups.join("\n")} placeholder="Daywalker Admins" className={inputCls} />
                  </Field>
                </ActionForm>
              )}
              <div className="flex flex-wrap gap-2">
                <ActionForm action={createScimTokenAction} submit={c.scim.enabled ? "Replace token" : "Turn on provisioning"} tone="ghost" secretLabel="SCIM token">
                  <input type="hidden" name="instanceId" value={id} />
                  <input type="hidden" name="connectionId" value={c.id} />
                </ActionForm>
                {c.scim.enabled && (
                  <ConfirmAction action={revokeScimTokenAction} label="Turn off" confirmLabel="Yes, turn off" prompt="Turn off provisioning? The identity provider will stop being able to add or remove people.">
                    <input type="hidden" name="instanceId" value={id} />
                    <input type="hidden" name="connectionId" value={c.id} />
                  </ConfirmAction>
                )}
              </div>
            </div>
            <div className="flex flex-wrap gap-2">
              <ActionForm action={toggleSsoAction} submit={c.enabled ? "Disable" : "Enable"} tone="ghost">
                <input type="hidden" name="instanceId" value={id} />
                <input type="hidden" name="connectionId" value={c.id} />
                <input type="hidden" name="enabled" value={c.enabled ? "false" : "true"} />
              </ActionForm>
              <ActionForm action={requireSsoAction} submit={c.ssoRequired ? "Allow other sign-in methods" : "Require SSO"} tone="ghost">
                <input type="hidden" name="instanceId" value={id} />
                <input type="hidden" name="connectionId" value={c.id} />
                <input type="hidden" name="ssoRequired" value={c.ssoRequired ? "false" : "true"} />
              </ActionForm>
              <ConfirmAction action={deleteSsoAction} label="Delete" confirmLabel="Yes, delete" prompt="Delete this connection? People at these domains won't be able to use SSO until you add it again.">
                <input type="hidden" name="instanceId" value={id} />
                <input type="hidden" name="connectionId" value={c.id} />
              </ConfirmAction>
            </div>
          </div>
        </Card>
      ))}
      <Card title="Add a connection" description="Paste the identity provider's metadata XML, or fill in its details by hand.">
        <ActionForm action={createSsoAction} submit="Create connection" className="max-w-2xl space-y-4" resetOnSuccess>
          <input type="hidden" name="instanceId" value={id} />
          <div className="grid gap-4 sm:grid-cols-2">
            <Field label="Name"><input name="name" required maxLength={100} placeholder="Acme Corp (Okta)" className={inputCls} /></Field>
            <Field label="Email domains" hint="Separate with spaces or commas."><input name="domains" required placeholder="acme.com acme.co.uk" className={inputCls} /></Field>
          </div>
          <Field label="Organization (optional)" hint="New users from this connection join it automatically.">
            <select name="organizationId" defaultValue="" className={inputCls}>
              <option value="">None</option>
              {orgs.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}
            </select>
          </Field>
          <Field label="Identity provider metadata XML">
            <textarea name="metadataXml" rows={5} placeholder="<EntityDescriptor …>" className={`${inputCls} font-mono text-xs`} />
          </Field>
          <details className="text-sm">
            <summary className="cursor-pointer font-medium">Or enter the details by hand</summary>
            <div className="mt-3 space-y-4">
              <Field label="IdP entity ID (issuer)"><input name="idpEntityId" className={`${inputCls} font-mono`} /></Field>
              <Field label="IdP sign-in URL (HTTP-Redirect)"><input name="ssoUrl" type="url" placeholder="https://" className={`${inputCls} font-mono`} /></Field>
              <Field label="IdP logout URL (optional)"><input name="sloUrl" type="url" placeholder="https://" className={`${inputCls} font-mono`} /></Field>
              <Field label="IdP signing certificate"><textarea name="certificate" rows={4} placeholder="-----BEGIN CERTIFICATE-----" className={`${inputCls} font-mono text-xs`} /></Field>
            </div>
          </details>
        </ActionForm>
      </Card>
    </div>
  );
}
