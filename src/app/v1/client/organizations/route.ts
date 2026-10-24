import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { createOrg, myOrgs } from "@/lib/auth/orgs";

export const OPTIONS = preflight;

/** Organizations the signed-in user belongs to, with their role in each. */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json({ organizations: await myOrgs(ctx.inst.id, s.userId) });
});

/** Create an organization; the creator gets the instance's creator role (admin by default). */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const { name } = z.object({ name: z.string().trim().min(1).max(80) }).parse(await req.json());
  return ctx.json({ organization: await createOrg(ctx.inst, s.userId, name) }, { status: 201 });
});
