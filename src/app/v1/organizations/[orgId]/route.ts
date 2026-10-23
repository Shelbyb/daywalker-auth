import { NextResponse } from "next/server";
import { z } from "zod";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { getOrg, setOrgTwoFactor } from "@/lib/auth/orgs";

type Ctx = { params: Promise<{ orgId: string }> };

/** Backend API: one organization. */
export const GET = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const o = await getOrg(inst.id, (await params).orgId);
  if (!o) throw errors.notFound("Organization not found");
  return NextResponse.json({ id: o.id, name: o.name, slug: o.slug, requireTwoFactor: o.requireTwoFactor, createdAt: o.createdAt });
});

/** Backend API: `{ requireTwoFactor }`. Members without two-factor lose this organization's claims until they turn it on. */
export const PATCH = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const { requireTwoFactor } = z.object({ requireTwoFactor: z.boolean() }).strict().parse(await req.json());
  const orgId = (await params).orgId;
  await setOrgTwoFactor(inst.id, orgId, null, requireTwoFactor);
  return NextResponse.json({ id: orgId, requireTwoFactor });
});
