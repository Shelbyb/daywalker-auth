import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { verifyInput, verifySignInCode } from "@/lib/auth/email-sign-in";
import { completeFirstFactor } from "@/lib/auth/complete-sign-in";

export const OPTIONS = preflight;

export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const input = verifyInput.parse(await req.json());
  await ctx.limit("esi_verify", 30, 900);
  const r = await verifySignInCode(ctx.inst, input.email, input.code);
  return completeFirstFactor(req, ctx, r.userId, r.method);
});
