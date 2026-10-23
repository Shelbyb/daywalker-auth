import Link from "next/link";
import { ssoFor } from "@/lib/dashboard";
import { requireUser } from "../../../guard";
import { createSsoAction, deleteSsoAction, requireSsoAction, toggleSsoAction } from "../../../actions";
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
            <p className="text-xs text-stone-500">
              Or upload the metadata from <span className="font-mono">{c.spEntityId}</span>. The NameID or an <span className="font-mono">email</span> attribute must carry the user&apos;s email, and assertions must be signed.
            </p>
            <div className="text-xs text-stone-500">
              Signing certificate{c.certificates.length > 1 ? "s" : ""}: {c.certificates.map((x) => <span key={x.fingerprint256} className="mr-3 inline-block">{x.subject.split("\n").find((l) => l.startsWith("CN=")) ?? "certificate"} · expires {new Date(x.validTo).toLocaleDateString("en-US", { year: "numeric", month: "short", day: "numeric" })}</span>)}
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
              <Field label="IdP signing certificate"><textarea name="certificate" rows={4} placeholder="-----BEGIN CERTIFICATE-----" className={`${inputCls} font-mono text-xs`} /></Field>
            </div>
          </details>
        </ActionForm>
      </Card>
    </div>
  );
}
