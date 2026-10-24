import { NextResponse } from "next/server";
import { z } from "zod";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { listDomains, addDomain } from "@/lib/auth/org-domains";

type Ctx = { params: Promise<{ orgId: string }> };

export const GET = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json({ data: await listDomains(inst, (await params).orgId, null) });
});

export const POST = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const { domain } = z.object({ domain: z.string().max(253) }).parse(await req.json());
  return NextResponse.json(await addDomain(inst, (await params).orgId, null, domain), { status: 201 });
});
