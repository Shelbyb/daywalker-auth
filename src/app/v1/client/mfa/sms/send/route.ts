import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { sendSmsChallenge } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** Text a code to the signed-in user's phone, to confirm a change on the account page. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("sms_send_ip", 20, 3600);
  return ctx.json(await sendSmsChallenge(ctx.inst, s.userId));
});
