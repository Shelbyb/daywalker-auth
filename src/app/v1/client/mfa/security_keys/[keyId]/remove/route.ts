import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { removeSecurityKey } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** Remove a security key. Needs a current code (authenticator, texted or backup). */
export const POST = handler(async (req: Request, { params }: { params: Promise<{ keyId: string }> }) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("mfa_disable", 10, 900);
  const { code } = z.object({ code: z.string().trim().max(20).default("") }).parse(await req.json());
  await removeSecurityKey(s.userId, (await params).keyId, code, s.id);
  return ctx.json({ removed: true });
});
