import { handler, errors } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { pendingUser, sendSmsChallenge } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** During sign-in (password already checked): text a code to the account's phone. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("sms_send_ip", 20, 3600);
  const userId = await pendingUser(ctx.inst.id, ctx.twoFactorToken);
  if (!userId) throw errors.unauthorized("Your sign-in attempt expired. Please sign in again");
  return ctx.json(await sendSmsChallenge(ctx.inst, userId));
});
