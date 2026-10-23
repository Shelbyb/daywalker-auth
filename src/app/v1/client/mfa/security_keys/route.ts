import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { listSecurityKeys } from "@/lib/auth/security-keys";

export const OPTIONS = preflight;

/** The signed-in user's security keys (names and dates only). */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json({ securityKeys: await listSecurityKeys(s.userId) });
});
