import Link from "next/link";
import { COMPONENT_LABELS, getHealth, type Component, type Level } from "@/lib/health";

export const dynamic = "force-dynamic";
export const metadata = { title: "Status" };

const TEXT: Record<Level, string> = { ok: "Operational", degraded: "Degraded", down: "Outage" };
const HEADLINE: Record<Level, string> = {
  ok: "All systems operational",
  degraded: "Some systems are degraded",
  down: "We are having an outage",
};
const TONE: Record<Level, string> = {
  ok: "bg-emerald-100 text-emerald-800",
  degraded: "bg-amber-100 text-amber-900",
  down: "bg-red-100 text-red-800",
};

/** Public status page. Shows only ok / degraded / down per component: no versions, hosts, counts or error text. */
export default async function StatusPage() {
  const h = await getHealth().catch(() => null);
  const status: Level = h?.status ?? "down";
  return (
    <main className="mx-auto max-w-3xl px-6 py-14">
      {/* Re-check every minute without any script. */}
      <meta httpEquiv="refresh" content="60" />
      <Link href="/" className="text-sm text-stone-500 hover:text-ink">← Daywalker Auth</Link>
      <h1 className="mt-6 text-3xl font-semibold text-ink">Status</h1>
      <p role="status" className={`mt-4 inline-block rounded-lg px-4 py-2 text-sm font-medium ${TONE[status]}`}>{HEADLINE[status]}</p>
      <ul className="mt-8 divide-y divide-stone-200 rounded-lg border border-stone-200">
        {(Object.keys(COMPONENT_LABELS) as Component[]).map((c) => {
          const level: Level = h?.components[c] ?? "down";
          return (
            <li key={c} className="flex items-center justify-between gap-4 px-4 py-3">
              <span className="text-stone-800">{COMPONENT_LABELS[c]}</span>
              <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${TONE[level]}`}>{TEXT[level]}</span>
            </li>
          );
        })}
      </ul>
      <p className="mt-4 text-xs text-stone-500">
        Checked {h ? new Date(h.checkedAt).toISOString().replace("T", " ").slice(0, 19) + " UTC" : "just now"}. This page refreshes every minute.
        Machine-readable: <Link href="/v1/health" className="underline">/v1/health</Link>.
      </p>
    </main>
  );
}
