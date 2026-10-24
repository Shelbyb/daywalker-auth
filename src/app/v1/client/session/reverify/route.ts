import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { reverify, reverifyInput, reverifyOptions } from "@/lib/auth/stepup";

export const OPTIONS = preflight;

/** What this person can use to prove themselves again (password, passkey, authenticator, text, security key, backup code, emailed code). */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("reverify_options", 60, 900);
  return ctx.json(await reverifyOptions(s.userId));
});

/**
 * Step-up: prove one factor again. `{ factor: "password", password }`, `{ factor: "code", code, method? }`
 * (authenticator, texted or backup code), `{ factor: "email_code", code }` or `{ factor: "security_key" }`
 * (after `mfa/security_keys/confirm`). Returns a fresh token whose `fva` shows the new ages.
 */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("reverify", 30, 900);
  const input = reverifyInput.parse(await req.json());
  return ctx.json(await reverify(ctx.inst, s, input, ctx.origin, ctx.refreshToken));
});
