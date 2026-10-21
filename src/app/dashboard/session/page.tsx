import { notFound } from "next/navigation";
import { dashboardEnabled } from "@/lib/dashboard";
import { SessionGate } from "./session-gate";

export const metadata = { title: "Signing you in…", robots: { index: false } };
export const dynamic = "force-dynamic";

/** Landing spot when the dashboard has no valid session token: refresh it, or go to sign-in. */
export default async function Page({ searchParams }: { searchParams: Promise<{ next?: string }> }) {
  if (!dashboardEnabled()) notFound();
  const { next } = await searchParams;
  // Only same-site paths under /dashboard: never an open redirect.
  const target = next && /^\/dashboard(\/[A-Za-z0-9_\-./]*)?$/.test(next) ? next : "/dashboard";
  return <SessionGate pk={process.env.PLATFORM_PUBLISHABLE_KEY!} target={target} />;
}
