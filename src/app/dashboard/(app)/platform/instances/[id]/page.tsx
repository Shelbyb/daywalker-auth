import { Suspense } from "react";
import Link from "next/link";
import { IMPERSONATION_MINUTES, instanceUsers } from "@/lib/platform";
import { requirePlatformPage } from "../../../guard";
import { ConfirmAction } from "../../../forms";
import { Badge, EmptyState, PageHeader, Skeleton } from "../../../ui";
import { btnCls, inputCls } from "../../../styles";
import { fmtDateTime, guarded } from "../../../server";
import { impersonateAction } from "../../actions";
import { Pager, pageNum, pageSize } from "../../../pager";

export const metadata = { title: "Instance users" };

async function Users({ id, search, page, size }: { id: string; search?: string; page: number; size: number }) {
  const { instance, users } = await guarded(() => instanceUsers(id, { search, limit: size + 1, offset: (page - 1) * size }));
  const base = `/dashboard/platform/instances/${encodeURIComponent(id)}`;
  return (
    <div className="space-y-4">
      <p className="text-sm text-stone-600">
        <span className="font-medium text-ink">{instance.name}</span> <Badge tone={instance.environment === "production" ? "warn" : "neutral"}>{instance.environment}</Badge>{" "}
        <Link href={`/dashboard/instances/${encodeURIComponent(instance.id)}`} className="ml-2 underline decoration-stone-300 underline-offset-2 hover:decoration-dawn">Manage instance</Link>
      </p>
      {!users.length ? (
        <EmptyState title="No users">{search ? "No user has exactly that email or ID." : "This instance has no users yet."}</EmptyState>
      ) : (
        <ul className="divide-y divide-stone-100 rounded-xl border border-stone-200 bg-white text-sm">
          {users.slice(0, size).map((u) => (
            <li key={u.id} className="flex flex-wrap items-start justify-between gap-3 p-3">
              <span className="min-w-0">
                <span className="font-medium">{u.email ?? "No email"}</span> {u.name && <span className="text-stone-500">({u.name})</span>}{" "}
                {u.banned && <Badge tone="bad">suspended</Badge>} {u.twoFactorEnabled && <Badge tone="good">2FA</Badge>}
                <span className="block font-mono text-xs text-stone-500">{u.id}</span>
                <span className="block text-xs text-stone-500">Last sign-in {fmtDateTime(u.lastSignInAt)}</span>
              </span>
              {!u.banned && (
                <ConfirmAction
                  action={impersonateAction}
                  label="Impersonate"
                  confirmLabel="Start impersonating"
                  tone="primary"
                  prompt={`You'll be signed in as this user in this browser for ${IMPERSONATION_MINUTES} minutes. The customer and the user aren't told; it's recorded in the platform audit log with your reason.`}
                >
                  <input type="hidden" name="instanceId" value={instance.id} />
                  <input type="hidden" name="userId" value={u.id} />
                  <label className="block text-xs">
                    <span className="mb-1 block font-medium">Reason (required)</span>
                    <input name="reason" required minLength={10} maxLength={500} placeholder="Support ticket #1234: can't see billing page" className={inputCls} />
                  </label>
                </ConfirmAction>
              )}
            </li>
          ))}
        </ul>
      )}
      {!search && (
        <Pager base={base} size={size} page={page} hasNext={users.length > size} />
      )}
    </div>
  );
}

export default async function PlatformInstanceUsers({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const { id } = await params;
  const sp = await searchParams;
  const search = typeof sp.q === "string" ? sp.q.slice(0, 254) : undefined;
  const page = pageNum(sp);
  const size = pageSize(sp);
  await requirePlatformPage(`/dashboard/platform/instances/${encodeURIComponent(id)}`);
  return (
    <div className="space-y-6">
      <PageHeader
        title="Users"
        description="Impersonating opens a short session as the user in this browser (hosted account page and the customer's app). You need two-factor on your own account. Each one is logged with your reason."
      />
      <form method="get" className="flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="mb-1 block font-medium">Find a user</span>
          <input name="q" defaultValue={search ?? ""} placeholder="Exact email or user_…" className={`${inputCls} w-72`} />
        </label>
        <button className={btnCls.ghost}>Find</button>
      </form>
      <Suspense key={`${search}:${page}:${size}`} fallback={<Skeleton lines={6} />}>
        <Users id={id} search={search} page={page} size={size} />
      </Suspense>
    </div>
  );
}
