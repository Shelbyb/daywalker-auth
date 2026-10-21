import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { startTotpEnrollment } from "@/lib/auth/mfa";
import { getUser } from "@/lib/auth/users";

export const OPTIONS = preflight;

/** Begin authenticator-app setup. Returns the secret and an otpauth:// URI for a QR code. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const user = await getUser(ctx.inst.id, s.userId);
  const label = user?.emailAddresses.find((e) => e.primary)?.email ?? s.userId;
  return ctx.json(await startTotpEnrollment(ctx.inst, s.userId, label));
});
