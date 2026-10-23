import { z } from "zod";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireFreshSession } from "@/lib/auth/require-session";
import { confirmSecurityKeyEnrollment } from "@/lib/auth/mfa";
import { readCredential } from "@/lib/auth/webauthn-input";

export const OPTIONS = preflight;

/** Step 2: the key's answer. Returns backup codes (shown once) if this turned two-factor on. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireFreshSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("security_key_reg", 20, 900);
  const body = await readCredential<RegistrationResponseJSON>(req, { name: z.string().max(60).optional() });
  const r = await confirmSecurityKeyEnrollment(ctx.inst, s.userId, s.id, body.response, body.name as string | undefined);
  return ctx.json(r, { status: 201 });
});
