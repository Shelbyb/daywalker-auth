import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { listMembers } from "@/lib/auth/orgs";

export const OPTIONS = preflight;

export const GET = handler(async (req: Request, { params }: { params: Promise<{ orgId: string }> }) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json({ members: await listMembers(ctx.inst.id, (await params).orgId, s.userId) });
});
