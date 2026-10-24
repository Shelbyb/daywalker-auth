import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { updateDomain, removeDomain, ENROLLMENT } from "@/lib/auth/org-domains";
import { roleKey } from "@/lib/auth/org-roles";

export const OPTIONS = preflight;
type Ctx = { params: Promise<{ orgId: string; domainId: string }> };

export const PATCH = handler(async (req: Request, { params }: Ctx) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const { orgId, domainId } = await params;
  const body = z.object({ enrollment: z.enum(ENROLLMENT).optional(), role: roleKey.nullable().optional() }).parse(await req.json());
  return ctx.json({ domain: await updateDomain(ctx.inst, orgId, s.userId, domainId, body) });
});

export const DELETE = handler(async (req: Request, { params }: Ctx) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const { orgId, domainId } = await params;
  await removeDomain(ctx.inst, orgId, s.userId, domainId);
  return ctx.json({ deleted: true });
});
