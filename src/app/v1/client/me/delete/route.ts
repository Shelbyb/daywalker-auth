import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { reauthInput, requestDeletion } from "@/lib/auth/account-deletion";

export const OPTIONS = preflight;

/** Schedules the signed-in user's account for deletion. Needs the password, a 2FA code or an emailed code; signs out everywhere. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const input = reauthInput.parse(await req.json().catch(() => ({})));
  const r = await requestDeletion(ctx.inst, s.userId, s.id, !!s.impersonatorId, input);
  return ctx.clearRefreshCookie(ctx.json(r));
});
