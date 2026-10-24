import { handler, clientIp } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { forgotPassword, forgotInput } from "@/lib/auth/recovery";
import { assertHuman } from "@/lib/auth/signup-protection";

export const OPTIONS = preflight;

/** Same response whether or not the email is registered. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("forgot", 10, 3600);
  const input = forgotInput.parse(await req.json());
  await assertHuman(ctx.inst, input.captchaToken, clientIp(req), "password_reset"); // sends an email
  await forgotPassword(ctx.inst, input.email);
  return ctx.json({ sent: true });
});
