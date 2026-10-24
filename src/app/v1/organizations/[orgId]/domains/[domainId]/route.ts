import { NextResponse } from "next/server";
import { z } from "zod";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { updateDomain, removeDomain, ENROLLMENT } from "@/lib/auth/org-domains";
import { roleKey } from "@/lib/auth/org-roles";

type Ctx = { params: Promise<{ orgId: string; domainId: string }> };

export const PATCH = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const { orgId, domainId } = await params;
  const body = z.object({ enrollment: z.enum(ENROLLMENT).optional(), role: roleKey.nullable().optional() }).parse(await req.json());
  return NextResponse.json(await updateDomain(inst, orgId, null, domainId, body));
});

export const DELETE = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const { orgId, domainId } = await params;
  await removeDomain(inst, orgId, null, domainId);
  return NextResponse.json({ id: domainId, deleted: true });
});
