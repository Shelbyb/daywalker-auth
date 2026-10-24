import Link from "next/link";
import { requireUser } from "../../guard";
import { Badge } from "../../ui";
import { details } from "../../server";
import { Tabs } from "./tabs";

export default async function InstanceLayout({ children, params }: { children: React.ReactNode; params: Promise<{ id: string }> }) {
  const { id } = await params;
  const base = `/dashboard/instances/${encodeURIComponent(id)}`;
  const { userId } = await requireUser(base);
  const inst = await details(userId, id); // 404s for anything this user doesn't own
  return (
    <div className="space-y-6">
      <div>
        <Link href="/dashboard" className="text-sm text-stone-500 hover:text-ink">&larr; All instances</Link>
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <h1 className="text-2xl font-semibold tracking-tight">{inst.name}</h1>
          <Badge tone={inst.environment === "production" ? "warn" : "neutral"}>{inst.environment}</Badge>
          <span className="text-sm text-stone-500">{inst.userCount} {inst.userCount === 1 ? "user" : "users"}</span>
        </div>
      </div>
      {inst.environment === "development" && (
        <p role="note" className="rounded-lg border border-amber-300 bg-amber-50 px-3 py-2 text-sm text-amber-900">
          Development instance: for building and testing. Its users and keys are separate from production.
        </p>
      )}
      <Tabs base={base}>{children}</Tabs>
    </div>
  );
}
