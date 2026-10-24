import { handler, clientIp } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { startInput, startPasskeySignUp } from "@/lib/auth/passkey-signup";
import { assertHuman } from "@/lib/auth/signup-protection";

export const OPTIONS = preflight;

/** Step 1 of signing up with a passkey: emails a code. The answer never says whether the address has an account. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("sign_up", 10, 3600);
  const input = startInput.parse(await req.json());
  await assertHuman(ctx.inst, input.captchaToken, clientIp(req), "signup");
  await startPasskeySignUp(ctx.inst, input);
  return ctx.json({ sent: true });
});
