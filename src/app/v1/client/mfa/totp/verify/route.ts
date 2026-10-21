import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { confirmTotpEnrollment } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** Confirm setup with a first code. Returns 10 backup codes, shown only this once. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("mfa_verify", 20, 900);
  const { code } = z.object({ code: z.string().trim() }).parse(await req.json());
  return ctx.json({ enabled: true, backupCodes: await confirmTotpEnrollment(s.userId, code) });
});
