import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { revokeInvitation } from "@/lib/auth/orgs";

export const OPTIONS = preflight;

export const DELETE = handler(async (req: Request, { params }: { params: Promise<{ orgId: string; invitationId: string }> }) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const { orgId, invitationId } = await params;
  await revokeInvitation(ctx.inst.id, orgId, s.userId, invitationId);
  return ctx.json({ revoked: true });
});
