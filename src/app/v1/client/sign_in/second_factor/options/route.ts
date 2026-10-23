import { handler, errors } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { pendingUser, twoFactorMethods } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** During sign-in: which second factors the account has (the phone is masked). */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("second_factor", 30, 900);
  const userId = await pendingUser(ctx.inst.id, ctx.twoFactorToken);
  if (!userId) throw errors.unauthorized("Your sign-in attempt expired. Please sign in again");
  const m = await twoFactorMethods(userId);
  return ctx.json({ totp: m.totp, sms: m.sms, securityKey: m.securityKeys > 0, backupCodes: m.backupCodes > 0 });
});
