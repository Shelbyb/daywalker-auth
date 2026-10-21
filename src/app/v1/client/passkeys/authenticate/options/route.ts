import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { authenticationOptions } from "@/lib/auth/passkeys";

export const OPTIONS = preflight;

/** Step 1 of signing in with a passkey. No email needed: the passkey identifies the account. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("passkey_auth_opts", 60, 300);
  return ctx.json(await authenticationOptions(ctx.inst));
});
