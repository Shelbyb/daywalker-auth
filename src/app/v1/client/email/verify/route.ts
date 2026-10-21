import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { verifyEmail, verifyInput } from "@/lib/auth/recovery";
import { getUser } from "@/lib/auth/users";

export const OPTIONS = preflight;

export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("verify", 20, 900);
  await verifyEmail(ctx.inst, s.userId, verifyInput.parse(await req.json()).code);
  return ctx.json({ user: await getUser(ctx.inst.id, s.userId) });
});
