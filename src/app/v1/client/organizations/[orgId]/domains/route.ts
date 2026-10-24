import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { listDomains, addDomain } from "@/lib/auth/org-domains";

export const OPTIONS = preflight;
type Ctx = { params: Promise<{ orgId: string }> };

/** Domains the organization claimed (needs org:manage). */
export const GET = handler(async (req: Request, { params }: Ctx) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json({ domains: await listDomains(ctx.inst, (await params).orgId, s.userId) });
});

export const POST = handler(async (req: Request, { params }: Ctx) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const { domain } = z.object({ domain: z.string().max(253) }).parse(await req.json());
  return ctx.json({ domain: await addDomain(ctx.inst, (await params).orgId, s.userId, domain) }, { status: 201 });
});
