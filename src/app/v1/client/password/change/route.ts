import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { changePassword, changePasswordInput } from "@/lib/auth/account";

export const OPTIONS = preflight;

/** Change password (needs the current one). Signs out all other sessions. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("password_change", 10, 900);
  const signedOut = await changePassword(ctx.inst, s.userId, s.id, changePasswordInput.parse(await req.json()));
  return ctx.json({ changed: true, otherSessionsSignedOut: signedOut });
});
