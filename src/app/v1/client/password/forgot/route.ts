import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { forgotPassword, forgotInput } from "@/lib/auth/recovery";

export const OPTIONS = preflight;

/** Same response whether or not the email is registered. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("forgot", 10, 3600);
  await forgotPassword(ctx.inst, forgotInput.parse(await req.json()).email);
  return ctx.json({ sent: true });
});
