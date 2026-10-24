import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { reauthRequirements, sendReauthCode } from "@/lib/auth/account-deletion";

export const OPTIONS = preflight;

/** What to ask the user for before deleting or exporting. */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json(await reauthRequirements(s.userId));
});

/** Emails a confirmation code (only for accounts with no password and no two-factor). */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await sendReauthCode(ctx.inst, s.userId);
  return ctx.json({ sent: true });
});
