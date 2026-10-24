import { Suspense } from "react";
import Link from "next/link";
import { activeImpersonations, siteAnalytics, staffNames } from "@/lib/platform";
import { requirePlatformPage } from "../guard";
import { ConfirmAction } from "../forms";
import { Badge, Card, EmptyState, PageHeader, Skeleton } from "../ui";
import { fmtDateTime } from "../server";
import { endImpersonationAction } from "./actions";

export const metadata = { title: "Overview" };

const n = (v: number) => v.toLocaleString("en-US");

function Stat({ label, value, hint }: { label: string; value: number; hint?: string }) {
  return (
    <div className="rounded-xl border border-stone-200 bg-white p-4 shadow-sm">
      <p className="text-xs font-medium uppercase tracking-wide text-stone-500">{label}</p>
      <p className="mt-1 text-2xl font-semibold tabular-nums">{n(value)}</p>
      {hint && <p className="mt-0.5 text-xs text-stone-500">{hint}</p>}
    </div>
  );
}

async function Analytics() {
  const a = await siteAnalytics();
  const max = Math.max(1, ...a.daily.map((d) => Math.max(d.signUps, d.signIns)));
  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Stat label="Accounts" value={a.accounts} />
        <Stat label="Instances" value={a.instances} hint={`${n(a.productionInstances)} production`} />
        <Stat label="End users" value={a.users} hint={`+${n(a.newUsers7d)} this week, +${n(a.newUsers30d)} in 30 days`} />
        <Stat label="Active sessions" value={a.activeSessions} />
        <Stat label="Sign-ins (24h)" value={a.signIns.d1} hint={`${n(a.signIns.active1d)} people`} />
        <Stat label="Sign-ins (7 days)" value={a.signIns.d7} hint={`${n(a.signIns.active7d)} people`} />
        <Stat label="Sign-ins (30 days)" value={a.signIns.d30} hint={`${n(a.signIns.active30d)} monthly active`} />
        <Stat label="Failed sign-ins (7 days)" value={a.failedSignIns7d} />
      </div>
      <Card title="Last 14 days" description="New end users and sign-ins per day, across every customer instance.">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[36rem] text-left text-sm">
            <thead className="text-xs uppercase text-stone-500">
              <tr><th className="py-1.5 pr-3">Day</th><th className="py-1.5 pr-3">Sign-ups</th><th className="py-1.5 pr-3">Sign-ins</th><th className="w-1/2 py-1.5" aria-hidden="true" /></tr>
            </thead>
            <tbody>
              {a.daily.map((d) => (
                <tr key={d.day} className="border-t border-stone-100">
                  <td className="whitespace-nowrap py-1.5 pr-3 font-mono text-xs text-stone-600">{d.day}</td>
                  <td className="py-1.5 pr-3 tabular-nums">{n(d.signUps)}</td>
                  <td className="py-1.5 pr-3 tabular-nums">{n(d.signIns)}</td>
                  <td className="py-1.5" aria-hidden="true">
                    <div className="h-1.5 rounded-full bg-dawn" style={{ width: `${(d.signIns / max) * 100}%` }} />
                    <div className="mt-0.5 h-1.5 rounded-full bg-ink/70" style={{ width: `${(d.signUps / max) * 100}%` }} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
      <Card title="Largest instances" description="By number of end users.">
        {a.topInstances.length ? (
          <ul className="divide-y divide-stone-100 text-sm">
            {a.topInstances.map((i) => (
              <li key={i.id} className="flex items-center justify-between gap-3 py-2">
                <Link href={`/dashboard/platform/instances/${encodeURIComponent(i.id)}`} className="truncate font-medium underline decoration-stone-300 underline-offset-2 hover:decoration-dawn">{i.name}</Link>
                <span className="flex items-center gap-2">
                  <Badge tone={i.environment === "production" ? "warn" : "neutral"}>{i.environment}</Badge>
                  <span className="tabular-nums text-stone-600">{n(i.users)}</span>
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-stone-500">No customer instances yet.</p>
        )}
      </Card>
    </div>
  );
}

async function Impersonations() {
  const rows = await activeImpersonations();
  const names = await staffNames(rows.map((r) => r.impersonatorId));
  if (!rows.length) return <EmptyState title="Nobody is being impersonated">Impersonation sessions you start show up here until they expire or you end them.</EmptyState>;
  return (
    <ul className="divide-y divide-stone-100 rounded-xl border border-stone-200 bg-white text-sm">
      {rows.map((r) => (
        <li key={r.id} className="flex flex-wrap items-center justify-between gap-3 p-3">
          <span>
            <span className="font-mono text-xs">{r.userId}</span> in <span className="font-medium">{r.instanceName}</span>
            <span className="block text-xs text-stone-500">by {names[r.impersonatorId ?? ""] ?? r.impersonatorId} · started {fmtDateTime(r.createdAt)} · ends {fmtDateTime(r.expiresAt)}</span>
          </span>
          <ConfirmAction action={endImpersonationAction} label="End" confirmLabel="End impersonation" prompt="The session stops working within a minute.">
            <input type="hidden" name="sessionId" value={r.id} />
          </ConfirmAction>
        </li>
      ))}
    </ul>
  );
}

export default async function PlatformHome() {
  await requirePlatformPage("/dashboard/platform");
  return (
    <div className="space-y-8">
      <PageHeader title="Site analytics" description="Usage across every customer instance. The dashboard's own instance is left out." />
      <Suspense fallback={<Skeleton lines={6} />}>
        <Analytics />
      </Suspense>
      <section className="space-y-3">
        <h2 className="text-base font-semibold">Active impersonations</h2>
        <Suspense fallback={<Skeleton lines={2} />}>
          <Impersonations />
        </Suspense>
      </section>
    </div>
  );
}
