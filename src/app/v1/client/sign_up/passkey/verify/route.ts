import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { verifyInput, verifyPasskeySignUpCode } from "@/lib/auth/passkey-signup";

export const OPTIONS = preflight;

/** Step 2: the emailed code. Returns a single-use token and the options for creating the passkey. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("passkey_signup_verify", 20, 3600);
  const input = verifyInput.parse(await req.json());
  return ctx.json(await verifyPasskeySignUpCode(ctx.inst, input));
});
