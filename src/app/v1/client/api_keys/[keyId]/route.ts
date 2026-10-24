import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { revokeForSession } from "@/lib/auth/api-keys";

export const OPTIONS = preflight;

export const DELETE = handler(async (req: Request, { params }: { params: Promise<{ keyId: string }> }) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json(await revokeForSession(ctx.inst, s.userId, (await params).keyId));
});
