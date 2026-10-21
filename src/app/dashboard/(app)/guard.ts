import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { dashboardEnabled, ensureAccount, getDashboardUser } from "@/lib/dashboard";

/**
 * The authoritative check for every dashboard page and action: the dashboard must be
 * enabled, and the session cookie must verify. Pages call this (the layout alone isn't
 * enough, because layouts don't re-run on every navigation).
 */
export async function requireUser(returnTo?: string) {
  if (!dashboardEnabled()) notFound();
  const u = await getDashboardUser();
  // Layouts don't know the URL, so the proxy passes it along (the session page re-validates it).
  if (!u) redirect(`/dashboard/session?next=${encodeURIComponent(returnTo ?? (await headers()).get("x-dw-path") ?? "/dashboard")}`);
  await ensureAccount(u.userId);
  return u;
}
