import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { invite, listInvitations } from "@/lib/auth/orgs";

export const OPTIONS = preflight;
type Ctx = { params: Promise<{ orgId: string }> };

export const GET = handler(async (req: Request, { params }: Ctx) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json({ invitations: await listInvitations(ctx.inst.id, (await params).orgId, s.userId) });
});

/** Email an invitation (admins only). Re-inviting the same address replaces the old link. */
export const POST = handler(async (req: Request, { params }: Ctx) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const body = z
    .object({ email: z.string().trim().toLowerCase().email().max(254), role: z.enum(["admin", "member"]).default("member") })
    .parse(await req.json());
  return ctx.json({ invitation: await invite(ctx.inst, (await params).orgId, s.userId, body.email, body.role) }, { status: 201 });
});
