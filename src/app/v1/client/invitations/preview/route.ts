import { z } from "zod";
import { handler, errors } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { previewInvitation } from "@/lib/auth/orgs";

export const OPTIONS = preflight;

/** Org name + role for an invite link, so the accept page can say what you're joining. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("invite_preview", 60, 300);
  const { token } = z.object({ token: z.string().min(10).max(200) }).parse(await req.json());
  const p = await previewInvitation(ctx.inst.id, token);
  if (!p) throw errors.badRequest("invalid_invitation", "This invitation is invalid, expired or was already used");
  return ctx.json(p);
});
