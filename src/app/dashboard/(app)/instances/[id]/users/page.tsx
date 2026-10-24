import { Suspense } from "react";
import { listUsers } from "@/lib/dashboard";
import { requireUser } from "../../../guard";
import { banUserAction, removeUserAction, unlockUserAction } from "../../../actions";
import { ConfirmAction } from "../../../forms";
import { Badge, EmptyState, PageHeader, Skeleton } from "../../../ui";
import { fmtDate, fmtDateTime, guarded } from "../../../server";
import { Pager, pageNum, pageSize } from "../../../pager";

export const metadata = { title: "Users" };

async function Users({ userId, id, page, size }: { userId: string; id: string; page: number; size: number }) {
  const rows = await guarded(() => listUsers(userId, id, { limit: size + 1, offset: (page - 1) * size }));
  const users = rows.slice(0, size);
  const hasNext = rows.length > size;
  const base = `/dashboard/instances/${encodeURIComponent(id)}/users`;
  if (!users.length)
    return <EmptyState title={page > 1 ? "No more users" : "No users yet"}>{page > 1 ? "You have reached the end of the list." : "People who sign up to your app will show up here."}</EmptyState>;
  return (
    <div className="space-y-3">
      <div className="overflow-x-auto rounded-xl border border-stone-200 bg-white">
        <table className="w-full min-w-[56rem] text-left text-sm">
          <thead className="border-b border-stone-200 text-xs uppercase text-stone-500">
            <tr><th className="p-3">Email</th><th className="p-3">Name</th><th className="p-3">Status</th><th className="p-3">Last sign-in</th><th className="p-3">Created</th><th className="p-3">Actions</th></tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-b border-stone-100 align-top last:border-0">
                <td className="p-3">
                  <span className="break-all">{u.email ?? "(no email)"}</span>{" "}
                  {u.email && (u.verified ? <Badge tone="good">verified</Badge> : <Badge>unverified</Badge>)}
                </td>
                <td className="p-3">{u.name ?? "-"}</td>
                <td className="space-x-1 p-3">
                  {u.twoFactorEnabled && <Badge tone="good">2FA</Badge>}
                  {u.banned && <Badge tone="bad">suspended</Badge>}
                  {u.lockedUntil && <Badge tone="bad">locked until {fmtDateTime(u.lockedUntil)}</Badge>}
                </td>
                <td className="p-3 text-stone-600">{fmtDateTime(u.lastSignInAt)}</td>
                <td className="p-3 text-stone-600">{fmtDate(u.createdAt)}</td>
                <td className="p-3">
                  <div className="flex flex-wrap items-start gap-2">
                    <ConfirmAction
                      action={banUserAction}
                      tone="ghost"
                      label={u.banned ? "Restore" : "Suspend"}
                      confirmLabel={u.banned ? "Yes, restore" : "Yes, suspend"}
                      prompt={u.banned ? "Let this user sign in again?" : "Suspend this user? They can't sign in."}
                    >
                      <input type="hidden" name="instanceId" value={id} />
                      <input type="hidden" name="targetId" value={u.id} />
                      <input type="hidden" name="banned" value={u.banned ? "false" : "true"} />
                    </ConfirmAction>
                    {u.lockedUntil && (
                      <ConfirmAction action={unlockUserAction} tone="ghost" label="Unlock" confirmLabel="Yes, unlock" prompt="Lift the lockout so this user can try again?">
                        <input type="hidden" name="instanceId" value={id} />
                        <input type="hidden" name="targetId" value={u.id} />
                      </ConfirmAction>
                    )}
                    <ConfirmAction action={removeUserAction} label="Delete" confirmLabel="Yes, delete" prompt="Permanently delete this user and their data? This can't be undone.">
                      <input type="hidden" name="instanceId" value={id} />
                      <input type="hidden" name="targetId" value={u.id} />
                    </ConfirmAction>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <Pager base={base} size={size} page={page} hasNext={hasNext} />
    </div>
  );
}

export default async function UsersPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const { id } = await params;
  const sp = await searchParams;
  const page = pageNum(sp);
  const size = pageSize(sp);
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/users${page > 1 ? `?page=${page}` : ""}`);
  return (
    <div className="space-y-6">
      <PageHeader title="Users" description="People who have signed up to this instance. Suspended users can't sign in until you restore them. Deleting a user is permanent." />
      <Suspense key={`${page}:${size}`} fallback={<Skeleton lines={6} />}>
        <Users userId={userId} id={id} page={page} size={size} />
      </Suspense>
    </div>
  );
}
