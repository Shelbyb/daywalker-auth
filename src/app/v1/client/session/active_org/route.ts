import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { setActiveOrg } from "@/lib/auth/orgs";
import { issueToken } from "@/lib/auth/sessions";
import { sha256 } from "@/lib/ids";

export const OPTIONS = preflight;

/** Switch the session's active organization (or null for personal). Returns a fresh JWT with org claims. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const { orgId } = z.object({ orgId: z.string().max(64).nullable() }).parse(await req.json());
  await setActiveOrg(ctx.inst.id, s.id, sha256(ctx.refreshToken!), s.userId, orgId);
  return ctx.json(await issueToken(ctx.inst, ctx.refreshToken, ctx.origin));
});
