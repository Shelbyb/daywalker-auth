import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { listRoles } from "@/lib/auth/org-roles";

export const OPTIONS = preflight;

/** Roles a signed-in person can choose from when inviting or changing members. */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json({ roles: await listRoles(ctx.inst.id) });
});
