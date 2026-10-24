import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { readCredential } from "@/lib/auth/webauthn-input";
import { reverifyWithPasskey } from "@/lib/auth/stepup";

export const OPTIONS = preflight;

/** Step 2: the passkey's answer. A user-verified passkey refreshes both the first and the second factor. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("reverify_passkey", 30, 900);
  const body = await readCredential<AuthenticationResponseJSON>(req);
  return ctx.json(await reverifyWithPasskey(ctx.inst, s, body.response, ctx.origin, ctx.refreshToken));
});
