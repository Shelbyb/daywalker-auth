import { Suspense } from "react";
import Link from "next/link";
import { allInstances } from "@/lib/platform";
import { requirePlatformPage } from "../../guard";
import { Badge, EmptyState, PageHeader, Skeleton } from "../../ui";
import { btnCls, inputCls } from "../../styles";
import { fmtDate } from "../../server";

export const metadata = { title: "Instances" };

const PAGE = 50;

async function List({ search, page }: { search?: string; page: number }) {
  const rows = await allInstances({ search, limit: PAGE + 1, offset: page * PAGE });
  if (!rows.length) return <EmptyState title="No instances">{search ? "Nothing matches that search." : "No customer has created an instance yet."}</EmptyState>;
  const qs = (p: number) => `/dashboard/platform/instances?${new URLSearchParams({ ...(search ? { q: search } : {}), ...(p ? { page: String(p) } : {}) })}`;
  return (
    <div className="space-y-3">
      <div className="overflow-x-auto rounded-xl border border-stone-200 bg-white">
        <table className="w-full min-w-[44rem] text-left text-sm">
          <thead className="border-b border-stone-200 text-xs uppercase text-stone-500">
            <tr><th className="p-3">Instance</th><th className="p-3">Account</th><th className="p-3">Users</th><th className="p-3">Created</th><th className="p-3" /></tr>
          </thead>
          <tbody>
            {rows.slice(0, PAGE).map((i) => (
              <tr key={i.id} className="border-b border-stone-100 last:border-0">
                <td className="p-3">
                  <span className="font-medium">{i.name}</span> <Badge tone={i.environment === "production" ? "warn" : "neutral"}>{i.environment}</Badge>
                  <span className="block font-mono text-xs text-stone-500">{i.id}</span>
                </td>
                <td className="p-3 text-stone-600">{i.accountName}<span className="block font-mono text-xs text-stone-400">{i.accountId}</span></td>
                <td className="p-3 tabular-nums">{i.users.toLocaleString("en-US")}</td>
                <td className="whitespace-nowrap p-3 text-stone-600">{fmtDate(i.createdAt)}</td>
                <td className="whitespace-nowrap p-3 text-right">
                  <Link href={`/dashboard/platform/instances/${encodeURIComponent(i.id)}`} className="mr-3 font-medium underline decoration-dawn decoration-2 underline-offset-4">Users</Link>
                  <Link href={`/dashboard/instances/${encodeURIComponent(i.id)}`} className="font-medium underline decoration-stone-300 decoration-2 underline-offset-4">Manage</Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <nav aria-label="Pagination" className="flex items-center justify-between text-sm">
        {page > 0 ? <Link href={qs(page - 1)} className="font-medium underline decoration-dawn decoration-2 underline-offset-4">&larr; Previous</Link> : <span />}
        {rows.length > PAGE ? <Link href={qs(page + 1)} className="font-medium underline decoration-dawn decoration-2 underline-offset-4">Next &rarr;</Link> : <span />}
      </nav>
    </div>
  );
}

export default async function PlatformInstances({ searchParams }: { searchParams: Promise<Record<string, string | string[] | undefined>> }) {
  const sp = await searchParams;
  const search = typeof sp.q === "string" ? sp.q.slice(0, 100) : undefined;
  const page = Math.min(Math.max(Number(typeof sp.page === "string" ? sp.page : 0) || 0, 0), 1000);
  await requirePlatformPage("/dashboard/platform/instances");
  return (
    <div className="space-y-6">
      <PageHeader title="Every instance" description="All customer instances. Manage opens the normal instance dashboard with full access; Users lets you impersonate. Opening an instance is recorded in the platform audit log." />
      <form method="get" className="flex flex-wrap items-end gap-3">
        <label className="text-sm">
          <span className="mb-1 block font-medium">Search</span>
          <input name="q" defaultValue={search ?? ""} placeholder="Name or ins_…" className={`${inputCls} w-72`} />
        </label>
        <button className={btnCls.ghost}>Search</button>
      </form>
      <Suspense key={`${search}:${page}`} fallback={<Skeleton lines={8} />}>
        <List search={search} page={page} />
      </Suspense>
    </div>
  );
}
