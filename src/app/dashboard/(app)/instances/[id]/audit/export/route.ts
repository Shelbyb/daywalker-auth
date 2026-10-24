import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { dashboardEnabled, getDashboardUser, ownedInstance } from "@/lib/dashboard";
import { exportResponse, parseRange } from "@/lib/audit-export";

/** Dashboard download of the audit log (NDJSON). Same data as the backend API's `audit_events/export`; signed-in owners only. */
export const GET = handler(async (req: Request, ctx: { params: Promise<{ id: string }> }) => {
  if (!dashboardEnabled()) return new NextResponse(null, { status: 404 });
  // A download link on another site must not be able to trigger an export.
  const site = req.headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") return new NextResponse(null, { status: 403 });
  const user = await getDashboardUser();
  if (!user) return new NextResponse(null, { status: 401 });
  const { id } = await ctx.params;
  const inst = await ownedInstance(user.userId, id);
  const u = new URL(req.url);
  return exportResponse(inst.id, parseRange(u.searchParams.get("from"), u.searchParams.get("to")), { type: "developer", id: user.userId });
});
