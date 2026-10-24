import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { cancelDeletionByToken } from "@/lib/auth/account-deletion";

export const OPTIONS = preflight;

/** Uses the one-time link from the "account scheduled for deletion" email. The user then signs in as usual. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const { token } = z.object({ token: z.string().min(20).max(100) }).parse(await req.json());
  await ctx.limit("cancel_deletion", 20, 900);
  await cancelDeletionByToken(ctx.inst, token);
  return ctx.json({ canceled: true });
});
