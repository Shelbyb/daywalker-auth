import { requireUser } from "../../../guard";
import { updateOrgSettingsAction, saveRoleAction, deleteRoleAction } from "../../../actions";
import { ActionForm, ConfirmAction } from "../../../forms";
import { Card, Field, PageHeader, PlanBadge, Toggle } from "../../../ui";
import { inputCls } from "../../../styles";
import { details } from "../../../server";
import { planAllows, planNeeded } from "@/lib/plans";
import { ensureAccount } from "@/lib/dashboard";
import { orgSettings } from "@/lib/org-settings";
import { listRoles } from "@/lib/auth/org-roles";

export const metadata = { title: "Organizations" };

export default async function OrganizationsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/organizations`);
  const inst = await details(userId, id);
  const o = orgSettings(inst);
  const locked = !(await planAllows(await ensureAccount(userId), "organization_settings"));
  const need = locked ? await planNeeded("organization_settings") : null;
  const roles = await listRoles(inst.id);
  const roleSelect = (name: string, value: string) => (
    <select name={name} defaultValue={value} className={inputCls}>
      {roles.map((r) => <option key={r.key} value={r.key}>{r.name}</option>)}
    </select>
  );
  return (
    <div className="space-y-6">
      <PageHeader title="Organizations" description="Rules for organizations your users create and join through your app. The backend API is exempt from these, except the membership limit." />
      {need && <p className="text-sm text-stone-600">Needs the <PlanBadge plan={need.name} /> plan. <a className="underline" href="/dashboard/billing">Billing</a></p>}
      <Card>
        <ActionForm action={updateOrgSettingsAction} submit="Save organization settings" className="max-w-xl space-y-5">
          <input type="hidden" name="instanceId" value={inst.id} />
          <fieldset disabled={locked} className="space-y-5 disabled:opacity-60">
          <Toggle name="enabled" defaultChecked={o.enabled} label="Enable organizations" description="When off, users can't create, join or accept invitations to organizations." />
          <Field label="Membership limit" hint="Most members one organization can have. Leave blank for unlimited.">
            <input name="membershipLimit" inputMode="numeric" defaultValue={o.membershipLimit ?? ""} placeholder="Unlimited" className={inputCls} />
          </Field>
          <Toggle name="allowUserCreation" defaultChecked={o.allowUserCreation} label="Allow users to create organizations" />
          <Field label="Creation limit per user" hint="Leave blank for unlimited.">
            <input name="creationLimit" inputMode="numeric" defaultValue={o.creationLimit ?? ""} placeholder="Unlimited" className={inputCls} />
          </Field>
          <Field label="Creator's role">{roleSelect("creatorRole", o.creatorRole)}</Field>
          <Field label="Default role for new members" hint="Used for invitations without a role and SSO just-in-time membership.">{roleSelect("defaultRole", o.defaultRole)}</Field>
          <Toggle name="allowAdminDelete" defaultChecked={o.allowAdminDelete} label="Allow admins to delete their organization" />
          <Toggle name="allowPersonalAccounts" defaultChecked={o.allowPersonalAccounts} label="Allow personal accounts" description="When off, a signed-in user must always have an active organization." />
          </fieldset>
        </ActionForm>
      </Card>
      <PageHeader title="Roles and permissions" description="Admin and Member are built in. Add roles with permission strings such as org:billing:manage. They appear in the session token as org_role and org_permissions; check them with has() / protect() in your backend. Admin always holds every permission you define." />
      <div className="space-y-4">
        {roles.map((r) => (
          <Card key={r.key}>
            {r.builtIn ? (
              <div className="space-y-1 text-sm">
                <p className="font-medium">{r.name} <span className="font-mono text-xs text-stone-500">{r.key}</span> <span className="text-xs text-stone-500">built in</span></p>
                <p className="break-words font-mono text-xs text-stone-600">{r.permissions.join(" ") || "-"}</p>
              </div>
            ) : (
              <div className="space-y-3">
                <ActionForm action={saveRoleAction} submit="Save role" className="max-w-xl space-y-3">
                  <input type="hidden" name="instanceId" value={inst.id} />
                  <input type="hidden" name="key" value={r.key} />
                  <fieldset disabled={locked} className="space-y-3 disabled:opacity-60">
                    <p className="font-mono text-xs text-stone-500">{r.key}</p>
                    <Field label="Name"><input name="name" defaultValue={r.name} className={inputCls} /></Field>
                    <Field label="Description"><input name="description" defaultValue={r.description ?? ""} className={inputCls} /></Field>
                    <Field label="Permissions" hint="Separated by spaces or commas."><textarea name="permissions" defaultValue={r.permissions.join(" ")} rows={2} className={inputCls + " font-mono"} /></Field>
                  </fieldset>
                </ActionForm>
                <ConfirmAction action={deleteRoleAction} label="Delete role" confirmLabel="Yes, delete" prompt="Delete this role? It must not be in use.">
                  <input type="hidden" name="instanceId" value={inst.id} />
                  <input type="hidden" name="key" value={r.key} />
                </ConfirmAction>
              </div>
            )}
          </Card>
        ))}
        <Card>
          <ActionForm action={saveRoleAction} submit="Add role" className="max-w-xl space-y-3">
            <input type="hidden" name="instanceId" value={inst.id} />
            <input type="hidden" name="isNew" value="true" />
            <fieldset disabled={locked} className="space-y-3 disabled:opacity-60">
              <Field label="Key" hint="Lowercase letters, digits, underscores. Appears in the token as org_role."><input name="key" placeholder="billing_manager" className={inputCls} /></Field>
              <Field label="Name"><input name="name" placeholder="Billing manager" className={inputCls} /></Field>
              <Field label="Description"><input name="description" className={inputCls} /></Field>
              <Field label="Permissions" hint="For example: org:read org:billing:manage"><textarea name="permissions" rows={2} className={inputCls + " font-mono"} /></Field>
            </fieldset>
          </ActionForm>
        </Card>
      </div>
    </div>
  );
}
