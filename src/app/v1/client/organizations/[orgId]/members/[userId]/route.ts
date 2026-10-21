import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { changeRole, removeMember } from "@/lib/auth/orgs";

export const OPTIONS = preflight;
type Ctx = { params: Promise<{ orgId: string; userId: string }> };

/** Change a member's role (admins only; the last admin can't be demoted). */
export const PATCH = handler(async (req: Request, { params }: Ctx) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const { orgId, userId } = await params;
  const { role } = z.object({ role: z.enum(["admin", "member"]) }).parse(await req.json());
  await changeRole(ctx.inst.id, orgId, s.userId, userId, role);
  return ctx.json({ userId, role });
});

/** Remove a member (admins), or leave (your own user ID). */
export const DELETE = handler(async (req: Request, { params }: Ctx) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const { orgId, userId } = await params;
  await removeMember(ctx.inst.id, orgId, s.userId, userId === "me" ? s.userId : userId);
  return ctx.json({ removed: true });
});
