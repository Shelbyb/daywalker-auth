import { handler, errors } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { revokeOwnSession } from "@/lib/auth/account";

export const OPTIONS = preflight;

/** Sign out one of your other devices. (Use DELETE /v1/client/session for this one.) */
export const POST = handler(async (req: Request, { params }: { params: Promise<{ sessionId: string }> }) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const { sessionId } = await params;
  if (sessionId === s.id) throw errors.badRequest("current_session", "Use sign out to end this session");
  await revokeOwnSession(ctx.inst.id, s.userId, sessionId);
  return ctx.json({ id: sessionId, status: "revoked" });
});
