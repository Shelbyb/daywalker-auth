import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { rotateBackupCodes } from "@/lib/auth/mfa";

export const OPTIONS = preflight;

/** Replace all backup codes. Requires a current code; old backup codes stop working. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await ctx.limit("mfa_rotate", 10, 900);
  const { code } = z.object({ code: z.string().trim() }).parse(await req.json());
  return ctx.json({ backupCodes: await rotateBackupCodes(s.userId, code) });
});
