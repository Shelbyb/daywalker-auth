import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { resetPassword, resetInput } from "@/lib/auth/recovery";

export const OPTIONS = preflight;

export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("reset", 20, 900);
  await resetPassword(ctx.inst, resetInput.parse(await req.json()));
  // Every session was revoked, including this browser's; clear its cookie too.
  return ctx.clearRefreshCookie(ctx.json({ reset: true }));
});
