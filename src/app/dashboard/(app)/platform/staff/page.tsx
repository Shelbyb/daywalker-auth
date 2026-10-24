import { listStaff } from "@/lib/platform";
import { requirePlatformPage } from "../../guard";
import { ActionForm, ConfirmAction } from "../../forms";
import { Badge, Card, Field, PageHeader } from "../../ui";
import { inputCls } from "../../styles";
import { fmtDate } from "../../server";
import { removeStaffAction, setStaffAction } from "../actions";

export const metadata = { title: "Staff" };

export default async function PlatformStaffPage() {
  const me = await requirePlatformPage("/dashboard/platform/staff", "admin");
  const staff = await listStaff();
  return (
    <div className="space-y-6">
      <PageHeader
        title="Platform staff"
        description="Platform admins can do everything, including these settings and this list. Platform users can see every instance, the analytics and the platform audit log, and impersonate. Staff need two-factor on to impersonate."
      />
      <Card>
        <ul className="divide-y divide-stone-100 text-sm">
          {staff.map((s) => (
            <li key={s.userId} className="flex flex-wrap items-center justify-between gap-3 py-2.5">
              <span>
                <span className="font-medium">{s.email ?? s.userId}</span> {s.name && <span className="text-stone-500">({s.name})</span>}{" "}
                <Badge tone={s.role === "admin" ? "warn" : "neutral"}>{s.role === "admin" ? "admin" : "user"}</Badge>{" "}
                {s.twoFactorEnabled ? <Badge tone="good">2FA</Badge> : <Badge tone="bad">no 2FA</Badge>}
                <span className="block text-xs text-stone-500">Since {fmtDate(s.createdAt)}</span>
              </span>
              {s.userId !== me.userId && (
                <ConfirmAction action={removeStaffAction} label="Remove" confirmLabel="Remove from staff" prompt="They lose platform access at once, and their impersonation sessions end.">
                  <input type="hidden" name="userId" value={s.userId} />
                </ConfirmAction>
              )}
            </li>
          ))}
        </ul>
      </Card>
      <Card title="Add or change a staff member" description="They must have signed in to the dashboard once.">
        <ActionForm action={setStaffAction} submit="Save" resetOnSuccess className="max-w-md space-y-4">
          <Field label="Email">
            <input name="email" type="email" required maxLength={254} autoComplete="off" className={inputCls} />
          </Field>
          <Field label="Role">
            <select name="role" defaultValue="user" className={inputCls}>
              <option value="user">Platform user</option>
              <option value="admin">Platform admin</option>
            </select>
          </Field>
        </ActionForm>
      </Card>
    </div>
  );
}
