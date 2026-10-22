import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { confirmSmsEnrollment } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** Confirm the phone with the texted code. Returns backup codes (shown once) when this turns two-factor on. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("sms_verify", 10, 900);
  const { code } = z.object({ code: z.string().trim().max(10) }).parse(await req.json());
  return ctx.json({ backupCodes: await confirmSmsEnrollment(s.userId, code) });
});
