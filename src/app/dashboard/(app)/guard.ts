import { headers } from "next/headers";
import { notFound, redirect } from "next/navigation";
import { dashboardEnabled, ensureAccount, getDashboardUser } from "@/lib/dashboard";
import { platformRole, type PlatformRole } from "@/lib/platform-staff";

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

/** Platform console pages: signed in AND platform staff (admin when asked). Anyone else gets a 404. */
export async function requirePlatformPage(returnTo: string, need: PlatformRole = "user") {
  const u = await requireUser(returnTo);
  const role = await platformRole(u.userId);
  if (!role || (need === "admin" && role !== "admin")) notFound();
  return { ...u, role };
}
