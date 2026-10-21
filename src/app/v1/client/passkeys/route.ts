import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { listPasskeys } from "@/lib/auth/passkeys";

export const OPTIONS = preflight;

export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json({ passkeys: await listPasskeys(s.userId) });
});
