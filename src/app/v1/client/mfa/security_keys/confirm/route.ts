import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { confirmWithSecurityKey } from "@/lib/auth/mfa";
import { readCredential } from "@/lib/auth/webauthn-input";

export const OPTIONS = preflight;

/**
 * Step 2: the key's answer. For the next two minutes this session may make one sensitive
 * two-factor change (add/remove a factor, turn it off, new backup codes) without typing a code.
 */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("security_key_confirm", 20, 900);
  const body = await readCredential<AuthenticationResponseJSON>(req);
  await confirmWithSecurityKey(ctx.inst, s.userId, s.id, body.response);
  return ctx.json({ confirmed: true });
});
