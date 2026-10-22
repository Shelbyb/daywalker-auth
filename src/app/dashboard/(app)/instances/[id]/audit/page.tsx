import { Suspense } from "react";
import Link from "next/link";
import { auditFor } from "@/lib/dashboard";
import { AUDIT_TYPES, RETENTION_DAYS } from "@/lib/audit";
import { requireUser } from "../../../guard";
import { Badge, EmptyState, PageHeader, Skeleton } from "../../../ui";
import { inputCls, btnCls } from "../../../styles";
import { fmtDateTime, guarded } from "../../../server";

export const metadata = { title: "Audit log" };

const label = (t: string) => t.replace(/[._]/g, " ");
const bad = new Set(["user.sign_in_failed", "user.sign_in_blocked", "user.two_factor_failed", "user.banned", "user.deleted", "api_key.revoked", "webhook.deleted"]);
const actorText = (a: { type: string; id: string | null }) => (a.type === "developer" ? "Dashboard" : a.type === "api" ? "Secret key" : a.type === "user" ? "User" : "System");

function Details({ data }: { data: Record<string, unknown> | null }) {
  if (!data) return <span className="text-stone-400">-</span>;
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-2 text-xs text-stone-600">
      {Object.entries(data).map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-stone-400">{k}</dt>
          <dd className="break-all">{v === null ? "-" : typeof v === "object" ? JSON.stringify(v) : String(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

async function Events({ userId, id, q }: { userId: string; id: string; q: { type?: string; target?: string; before?: string } }) {
  const { data, nextCursor } = await guarded(() => auditFor(userId, id, { ...q, limit: 50 }));
  const base = `/dashboard/instances/${encodeURIComponent(id)}/audit`;
  const qs = (extra: Record<string, string | undefined>) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries({ type: q.type, target: q.target, ...extra })) if (v) p.set(k, v);
    return p.size ? `${base}?${p}` : base;
  };
  if (!data.length)
    return <EmptyState title={q.before ? "No older events" : "Nothing logged yet"}>{q.type || q.target ? "No events match these filters." : "Sign-ins, security changes and settings changes will show up here."}</EmptyState>;
  return (
    <div className="space-y-3">
      <div className="overflow-x-auto rounded-xl border border-stone-200 bg-white">
        <table className="w-full min-w-[52rem] text-left text-sm">
          <thead className="border-b border-stone-200 text-xs uppercase text-stone-500">
            <tr><th className="p-3">When</th><th className="p-3">Event</th><th className="p-3">By</th><th className="p-3">Target</th><th className="p-3">Details</th></tr>
          </thead>
          <tbody>
            {data.map((e) => (
              <tr key={e.id} className="border-b border-stone-100 align-top last:border-0">
                <td className="whitespace-nowrap p-3 text-stone-600">{fmtDateTime(e.createdAt)}</td>
                <td className="p-3"><Badge tone={bad.has(e.type) ? "bad" : "neutral"}>{label(e.type)}</Badge></td>
                <td className="p-3 text-stone-600">{actorText(e.actor)}</td>
                <td className="p-3">
                  {e.target ? <Link href={qs({ target: e.target })} className="break-all font-mono text-xs underline decoration-stone-300 underline-offset-2 hover:decoration-dawn">{e.target}</Link> : <span className="text-stone-400">-</span>}
                </td>
                <td className="p-3"><Details data={e.data} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <nav aria-label="Pagination" className="flex items-center justify-between text-sm">
        {q.before ? <Link href={qs({})} className="font-medium underline decoration-dawn decoration-2 underline-offset-4">&larr; Newest</Link> : <span />}
        {nextCursor ? <Link href={qs({ before: nextCursor })} className="font-medium underline decoration-dawn decoration-2 underline-offset-4">Older &rarr;</Link> : <span />}
      </nav>
    </div>
  );
}

export default async function AuditPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const { id } = await params;
  const sp = await searchParams;
  const one = (k: string) => (typeof sp[k] === "string" ? (sp[k] as string).slice(0, 100) : undefined) || undefined;
  const type = (AUDIT_TYPES as readonly string[]).includes(one("type") ?? "") ? one("type") : undefined;
  const q = { type, target: one("target"), before: one("before") };
  const p = new URLSearchParams(Object.entries(q).filter(([, v]) => v) as [string, string][]);
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/audit${p.size ? `?${p}` : ""}`);
  return (
    <div className="space-y-6">
      <PageHeader title="Audit log" description={`Sign-ins, failed attempts, security changes and settings changes, newest first. Kept for ${RETENTION_DAYS} days. Details are stored encrypted.`} />
      <form method="get" className="flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="mb-1 block font-medium">Event</span>
          <select name="type" defaultValue={type ?? ""} className={`${inputCls} w-56`}>
            <option value="">All events</option>
            {AUDIT_TYPES.map((t) => <option key={t} value={t}>{label(t)}</option>)}
          </select>
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">Target ID</span>
          <input name="target" defaultValue={q.target ?? ""} placeholder="user_… or we_…" className={`${inputCls} w-64`} />
        </label>
        <button className={btnCls.ghost}>Filter</button>
        {(type || q.target) && <Link href={`/dashboard/instances/${encodeURIComponent(id)}/audit`} className="py-2 text-sm text-stone-600 underline underline-offset-4">Clear</Link>}
      </form>
      <Suspense key={JSON.stringify(q)} fallback={<Skeleton lines={8} />}>
        <Events userId={userId} id={id} q={q} />
      </Suspense>
    </div>
  );
}
