import { Suspense } from "react";
import Link from "next/link";
import { listInstances, requireDashboardUser } from "@/lib/dashboard";
import { requireUser } from "./guard";
import { createInstanceAction } from "./actions";
import { ActionForm } from "./forms";
import { Badge, Card, EmptyState, Field, PageHeader, Skeleton, inputCls } from "./ui";
import { fmtDate } from "./server";

export const metadata = { title: "Instances" };

async function Instances() {
  const { userId } = await requireDashboardUser();
  const list = await listInstances(userId);
  if (!list.length)
    return (
      <EmptyState title="No instances yet">
        An instance is one app (or one environment of an app, like development or production) with its own separate set of users, keys and settings. Create your first one below.
      </EmptyState>
    );
  return (
    <ul className="grid gap-3 sm:grid-cols-2">
      {list.map((i) => (
        <li key={i.id}>
          <Link href={`/dashboard/instances/${encodeURIComponent(i.id)}`} className="block rounded-xl border border-stone-200 bg-white p-4 shadow-sm transition hover:border-dawn focus-visible:outline-2 focus-visible:outline-dawn">
            <div className="flex items-center justify-between gap-2">
              <span className="truncate font-semibold">{i.name}</span>
              <Badge tone={i.environment === "production" ? "warn" : "neutral"}>{i.environment}</Badge>
            </div>
            <code className="mt-2 block truncate font-mono text-xs text-stone-600">{i.publishableKey}</code>
            <p className="mt-2 text-xs text-stone-500">Created {fmtDate(i.createdAt)}</p>
          </Link>
        </li>
      ))}
    </ul>
  );
}

export default async function DashboardHome() {
  await requireUser("/dashboard");
  return (
    <div className="space-y-8">
      <PageHeader title="Your instances" description="Each instance is a separate app or environment with its own users. Pick one to manage it, or create a new one." />
      <Suspense fallback={<Skeleton lines={4} />}>
        <Instances />
      </Suspense>
      <Card title="Create an instance" description="You'll get a publishable key (for your frontend) and a secret key (for your server). The secret is shown once.">
        <ActionForm action={createInstanceAction} submit="Create instance" resetOnSuccess showKeys secretLabel="Secret key" className="max-w-md space-y-4">
          <Field label="Name">
            <input name="name" required maxLength={60} placeholder="My app" autoComplete="off" className={inputCls} />
          </Field>
          <Field label="Environment" hint="Use development while building. Production keys start with sk_live_.">
            <select name="environment" defaultValue="development" className={inputCls}>
              <option value="development">development</option>
              <option value="production">production</option>
            </select>
          </Field>
        </ActionForm>
      </Card>
    </div>
  );
}
