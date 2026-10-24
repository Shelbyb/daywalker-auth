import { Suspense } from "react";
import Link from "next/link";
import { instanceNames, staffNames } from "@/lib/platform";
import { PLATFORM_AUDIT_TYPES, PLATFORM_RETENTION_DAYS, listPlatformAudit } from "@/lib/platform-audit";
import { requirePlatformPage } from "../../guard";
import { Badge, EmptyState, PageHeader, Skeleton } from "../../ui";
import { btnCls, inputCls } from "../../styles";
import { fmtDateTime } from "../../server";

export const metadata = { title: "Platform audit log" };

const label = (t: string) => t.replace(/[._]/g, " ");
const tone = (t: string) => (t.startsWith("impersonation.started") ? "warn" : t.endsWith("denied") || t === "staff.removed" ? "bad" : "neutral");

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

type Q = { type?: string; actor?: string; instance?: string; target?: string; before?: string };

async function Events({ q }: { q: Q }) {
  const { data, nextCursor } = await listPlatformAudit({ ...q, limit: 50 });
  const [actors, instances] = await Promise.all([staffNames(data.map((e) => e.actorId)), instanceNames(data.map((e) => e.instanceId))]);
  const base = "/dashboard/platform/audit";
  const qs = (extra: Partial<Q>) => {
    const p = new URLSearchParams();
    for (const [k, v] of Object.entries({ type: q.type, actor: q.actor, instance: q.instance, target: q.target, ...extra })) if (v) p.set(k, v);
    return p.size ? `${base}?${p}` : base;
  };
  if (!data.length) return <EmptyState title={q.before ? "No older events" : "Nothing logged yet"}>Impersonation, instance access, platform settings and staff changes show up here.</EmptyState>;
  return (
    <div className="space-y-3">
      <div className="overflow-x-auto rounded-xl border border-stone-200 bg-white">
        <table className="w-full min-w-[56rem] text-left text-sm">
          <thead className="border-b border-stone-200 text-xs uppercase text-stone-500">
            <tr><th className="p-3">When</th><th className="p-3">Event</th><th className="p-3">By</th><th className="p-3">Instance</th><th className="p-3">Target</th><th className="p-3">Details</th></tr>
          </thead>
          <tbody>
            {data.map((e) => (
              <tr key={e.id} className="border-b border-stone-100 align-top last:border-0">
                <td className="whitespace-nowrap p-3 text-stone-600">{fmtDateTime(e.createdAt)}</td>
                <td className="p-3"><Badge tone={tone(e.type)}>{label(e.type)}</Badge></td>
                <td className="p-3">{e.actorId ? <Link href={qs({ actor: e.actorId, before: undefined })} className="break-all text-xs underline decoration-stone-300 underline-offset-2 hover:decoration-dawn">{actors[e.actorId] ?? e.actorId}</Link> : "-"}</td>
                <td className="p-3">{e.instanceId ? <Link href={qs({ instance: e.instanceId, before: undefined })} className="break-all text-xs underline decoration-stone-300 underline-offset-2 hover:decoration-dawn">{instances[e.instanceId] ?? e.instanceId}</Link> : <span className="text-stone-400">-</span>}</td>
                <td className="p-3">{e.target ? <Link href={qs({ target: e.target, before: undefined })} className="break-all font-mono text-xs underline decoration-stone-300 underline-offset-2 hover:decoration-dawn">{e.target}</Link> : <span className="text-stone-400">-</span>}</td>
                <td className="p-3"><Details data={e.data} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <nav aria-label="Pagination" className="flex items-center justify-between text-sm">
        {q.before ? <Link href={qs({ before: undefined })} className="font-medium underline decoration-dawn decoration-2 underline-offset-4">&larr; Newest</Link> : <span />}
        {nextCursor ? <Link href={qs({ before: nextCursor })} className="font-medium underline decoration-dawn decoration-2 underline-offset-4">Older &rarr;</Link> : <span />}
      </nav>
    </div>
  );
}

export default async function PlatformAuditPage({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const one = (k: string) => (typeof sp[k] === "string" ? (sp[k] as string).slice(0, 100) : undefined) || undefined;
  const type = (PLATFORM_AUDIT_TYPES as readonly string[]).includes(one("type") ?? "") ? one("type") : undefined;
  const q: Q = { type, actor: one("actor"), instance: one("instance"), target: one("target"), before: one("before") };
  const p = new URLSearchParams(Object.entries(q).filter(([, v]) => v) as [string, string][]);
  await requirePlatformPage(`/dashboard/platform/audit${p.size ? `?${p}` : ""}`);
  const filtered = !!(q.type || q.actor || q.instance || q.target);
  return (
    <div className="space-y-6">
      <PageHeader title="Platform audit log" description={`What platform staff did: impersonation (with the reason given), opening customer instances, platform settings and staff changes. Only platform staff can see this; customers never do. Kept for ${PLATFORM_RETENTION_DAYS} days. Details are stored encrypted.`} />
      <form method="get" className="flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="mb-1 block font-medium">Event</span>
          <select name="type" defaultValue={type ?? ""} className={`${inputCls} w-56`}>
            <option value="">All events</option>
            {PLATFORM_AUDIT_TYPES.map((t) => <option key={t} value={t}>{label(t)}</option>)}
          </select>
        </label>
        <label className="text-sm">
          <span className="mb-1 block font-medium">Target ID</span>
          <input name="target" defaultValue={q.target ?? ""} placeholder="user_…" className={`${inputCls} w-56`} />
        </label>
        {q.actor && <input type="hidden" name="actor" value={q.actor} />}
        {q.instance && <input type="hidden" name="instance" value={q.instance} />}
        <button className={btnCls.ghost}>Filter</button>
        {filtered && <Link href="/dashboard/platform/audit" className="py-2 text-sm text-stone-600 underline underline-offset-4">Clear</Link>}
      </form>
      <Suspense key={JSON.stringify(q)} fallback={<Skeleton lines={8} />}>
        <Events q={q} />
      </Suspense>
    </div>
  );
}
