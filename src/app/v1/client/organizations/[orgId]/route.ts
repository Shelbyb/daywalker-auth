import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { renameOrg, deleteOrg } from "@/lib/auth/orgs";

export const OPTIONS = preflight;
type Ctx = { params: Promise<{ orgId: string }> };

export const PATCH = handler(async (req: Request, { params }: Ctx) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const { name } = z.object({ name: z.string().trim().min(1).max(80) }).parse(await req.json());
  await renameOrg(ctx.inst.id, (await params).orgId, s.userId, name);
  return ctx.json({ ok: true });
});

export const DELETE = handler(async (req: Request, { params }: Ctx) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await deleteOrg(ctx.inst.id, (await params).orgId, s.userId);
  return ctx.json({ deleted: true });
});
