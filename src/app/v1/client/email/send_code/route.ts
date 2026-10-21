import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { sendVerification } from "@/lib/auth/recovery";

export const OPTIONS = preflight;

export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await sendVerification(ctx.inst, s.userId);
  return ctx.json({ sent: true });
});
