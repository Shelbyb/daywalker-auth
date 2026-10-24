import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { acceptInvitation } from "@/lib/auth/orgs";

export const OPTIONS = preflight;

/** Join via an invite link. Must be signed in as the invited, verified email address. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("invite_accept", 30, 900);
  const { token } = z.object({ token: z.string().min(10).max(200) }).parse(await req.json());
  return ctx.json({ organization: await acceptInvitation(ctx.inst, s.userId, token) });
});
