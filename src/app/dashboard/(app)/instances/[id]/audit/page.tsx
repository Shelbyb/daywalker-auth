import { Suspense } from "react";
import Link from "next/link";
import { auditFor, auditExportFor } from "@/lib/dashboard";
import { AUDIT_TYPES, RETENTION_DAYS } from "@/lib/audit";
import { requireUser } from "../../../guard";
import { Badge, Card, EmptyState, Field, PageHeader, Skeleton, Toggle } from "../../../ui";
import { ActionForm } from "../../../forms";
import { verifyAuditAction, saveAuditExportAction, removeAuditExportAction, pushAuditExportAction, testAuditExportAction } from "../../../actions";
import { inputCls, btnCls } from "../../../styles";
import { fmtDateTime, guarded } from "../../../server";
import { Pager, pageSize } from "../../../pager";

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

async function Events({ userId, id, q, size }: { userId: string; id: string; q: { type?: string; target?: string; before?: string }; size: number }) {
  const { data, nextCursor } = await guarded(() => auditFor(userId, id, { ...q, limit: size }));
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
      <Pager base={base} params={{ type: q.type, target: q.target }} size={size} defaultSize={50} cursor={q.before} nextCursor={nextCursor} />
    </div>
  );
}

async function BucketExport({ userId, id }: { userId: string; id: string }) {
  const c = await guarded(() => auditExportFor(userId, id));
  return (
    <Card>
      <h2 className="text-sm font-semibold">Copy to your own bucket</h2>
      <p className="mt-1 max-w-2xl text-sm text-stone-600">
        Pushes new entries every 15 minutes to an S3-compatible bucket (AWS S3, Cloudflare R2, MinIO, Backblaze B2) as signed-in-order NDJSON files. A copy outside our database is what lets you prove later that nothing was rewritten.
        The keys are stored encrypted and are never shown again; give them write-only access to this bucket.
      </p>
      {c.configured && (
        <p className="mt-3 text-sm text-stone-600">
          {c.enabled ? "Active" : "Paused"} · key {c.accessKeyId} · pushed through entry {c.lastPushedSeq}
          {c.lastPushedAt ? ` (${fmtDateTime(c.lastPushedAt)})` : ""}
          {c.lastError && <span className="text-ember"> · last error: {c.lastError}</span>}
        </p>
      )}
      <ActionForm action={saveAuditExportAction} submit={c.configured ? "Save changes" : "Save bucket"} className="mt-4 grid max-w-2xl gap-4 sm:grid-cols-2">
        <input type="hidden" name="instanceId" value={id} />
        <Field label="Endpoint" hint="Blank for AWS S3. Otherwise your service's https origin."><input name="endpoint" defaultValue={c.configured ? (c.endpoint ?? "") : ""} placeholder="https://<account>.r2.cloudflarestorage.com" className={inputCls} /></Field>
        <Field label="Region" hint="us-east-1, or auto for R2."><input name="region" required defaultValue={c.configured ? c.region : ""} className={inputCls} /></Field>
        <Field label="Bucket"><input name="bucket" required defaultValue={c.configured ? c.bucket : ""} className={inputCls} /></Field>
        <Field label="Folder prefix" hint="Optional, e.g. daywalker/audit"><input name="prefix" defaultValue={c.configured ? c.prefix : ""} className={inputCls} /></Field>
        <Field label="Access key ID" hint={c.configured ? "Leave both key fields blank to keep the current keys." : undefined}><input name="accessKeyId" autoComplete="off" required={!c.configured} className={inputCls} /></Field>
        <Field label="Secret access key"><input name="secretAccessKey" type="password" autoComplete="new-password" required={!c.configured} className={inputCls} /></Field>
        <Toggle name="enabled" defaultChecked={c.configured ? c.enabled : true} label="Push automatically" />
        <Toggle name="pathStyle" defaultChecked={c.configured ? c.pathStyle : false} label="Path-style URLs" description="Needed by MinIO and some others." />
        <Toggle name="serverSideEncryption" defaultChecked={c.configured ? c.serverSideEncryption : false} label="Ask for server-side encryption (AES256)" />
      </ActionForm>
      {c.configured && (
        <div className="mt-4 flex flex-wrap gap-3">
          <ActionForm action={testAuditExportAction} submit="Test connection" tone="ghost" className="flex"><input type="hidden" name="instanceId" value={id} /></ActionForm>
          <ActionForm action={pushAuditExportAction} submit="Push now" tone="ghost" className="flex"><input type="hidden" name="instanceId" value={id} /></ActionForm>
          <ActionForm action={removeAuditExportAction} submit="Remove" tone="ghost" className="flex"><input type="hidden" name="instanceId" value={id} /></ActionForm>
        </div>
      )}
    </Card>
  );
}

export default async function AuditPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const { id } = await params;
  const sp = await searchParams;
  const one = (k: string) => (typeof sp[k] === "string" ? (sp[k] as string).slice(0, 100) : undefined) || undefined;
  const type = (AUDIT_TYPES as readonly string[]).includes(one("type") ?? "") ? one("type") : undefined;
  const q = { type, target: one("target"), before: one("before") };
  const size = pageSize(sp, 50);
  const p = new URLSearchParams(Object.entries(q).filter(([, v]) => v) as [string, string][]);
  const { userId } = await requireUser(`/dashboard/instances/${encodeURIComponent(id)}/audit${p.size ? `?${p}` : ""}`);
  return (
    <div className="space-y-6">
      <PageHeader title="Audit log" description={`Sign-ins, failed attempts, security changes and settings changes, newest first. Kept for ${RETENTION_DAYS} days. Details are stored encrypted. Every entry is hash-chained to the one before it, so edits, deletions and truncation are detectable.`} />
      <div className="flex flex-wrap items-start gap-3">
        <ActionForm action={verifyAuditAction} submit="Verify integrity" tone="ghost" className="flex flex-wrap items-start gap-3">
          <input type="hidden" name="instanceId" value={id} />
        </ActionForm>
        <a href={`/dashboard/instances/${encodeURIComponent(id)}/audit/export`} className={btnCls.ghost}>Download NDJSON</a>
      </div>
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
        {size !== 50 && <input type="hidden" name="size" value={size} />}
        <button className={btnCls.ghost}>Filter</button>
        {(type || q.target) && <Link href={`/dashboard/instances/${encodeURIComponent(id)}/audit`} className="py-2 text-sm text-stone-600 underline underline-offset-4">Clear</Link>}
      </form>
      <Suspense key={JSON.stringify({ q, size })} fallback={<Skeleton lines={8} />}>
        <Events userId={userId} id={id} q={q} size={size} />
      </Suspense>
      <Suspense fallback={<Skeleton lines={4} />}>
        <BucketExport userId={userId} id={id} />
      </Suspense>
    </div>
  );
}
