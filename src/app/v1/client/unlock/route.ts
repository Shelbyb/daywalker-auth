import { NextResponse } from "next/server";
import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { unlockWithToken } from "@/lib/auth/lockout";

export const OPTIONS = preflight;

/** Uses the one-time link from the "account locked" email. The user still signs in afterwards. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const { token } = z.object({ token: z.string().min(20).max(100) }).parse(await req.json());
  await ctx.limit("unlock", 20, 900);
  await unlockWithToken(ctx.inst, token);
  return ctx.json({ unlocked: true });
});
