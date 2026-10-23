import { handler, errors } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { pendingUser } from "@/lib/auth/mfa";
import { securityKeyAuthenticationOptions } from "@/lib/auth/security-keys";

export const OPTIONS = preflight;

/** During sign-in: the challenge for the person's security key. Needs the pending sign-in cookie. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("second_factor", 30, 900);
  const userId = await pendingUser(ctx.inst.id, ctx.twoFactorToken);
  if (!userId) throw errors.unauthorized("Your sign-in attempt expired. Please sign in again");
  return ctx.json(await securityKeyAuthenticationOptions(userId));
});
