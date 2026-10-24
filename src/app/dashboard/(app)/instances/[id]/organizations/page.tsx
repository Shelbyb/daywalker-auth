import { requireUser } from "../../../guard";
import { updateOrgSettingsAction } from "../../../actions";
import { ActionForm } from "../../../forms";
import { Card, Field, PageHeader, PlanBadge, Toggle } from "../../../ui";
import { inputCls } from "../../../styles";
import { details } from "../../../server";
import { planNeeded } from "@/lib/plans";
import { orgSettings } from "@/lib/org-settings";

export const metadata = { title: "Organizations" };

export default async function OrganizationsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/organizations`);
  const inst = await details(userId, id);
  const o = orgSettings(inst);
  const need = await planNeeded("organization_settings");
  const roleSelect = (name: string, value: string) => (
    <select name={name} defaultValue={value} className={inputCls}>
      <option value="admin">Admin</option>
      <option value="member">Member</option>
    </select>
  );
  return (
    <div className="space-y-6">
      <PageHeader title="Organizations" description="Rules for organizations your users create and join through your app. The backend API is exempt from these, except the membership limit." />
      {need && <p className="text-sm text-stone-600">Needs the <PlanBadge plan={need.name} /> plan. <a className="underline" href="/dashboard/billing">Billing</a></p>}
      <Card>
        <ActionForm action={updateOrgSettingsAction} submit="Save organization settings" className="max-w-xl space-y-5">
          <input type="hidden" name="instanceId" value={inst.id} />
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
        </ActionForm>
      </Card>
    </div>
  );
}
