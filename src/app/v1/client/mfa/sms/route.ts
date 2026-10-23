import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { startSmsEnrollment } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** Add a phone for two-factor: texts it a code. `code` (a current second factor) is required if two-factor is already on. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("sms_send_ip", 20, 3600);
  const { phone, code } = z.object({ phone: z.string().trim().max(32), code: z.string().trim().max(20).optional() }).parse(await req.json());
  return ctx.json(await startSmsEnrollment(ctx.inst, s.userId, phone, code, s.id));
});
