import { NextResponse } from "next/server";
import { z } from "zod";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { deleteEndpoint, getEndpoint, updateEndpoint } from "@/lib/webhooks";

type Ctx = { params: Promise<{ id: string }> };

export const GET = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json(await getEndpoint(inst.id, (await params).id));
});

export const PATCH = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const body = z
    .object({
      url: z.string().max(2000).optional(),
      events: z.array(z.string().max(64)).max(20).optional(),
      description: z.string().max(200).nullish(),
      enabled: z.boolean().optional(),
    })
    .parse(await req.json());
  return NextResponse.json(await updateEndpoint(inst.id, (await params).id, body));
});

export const DELETE = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const { id } = await params;
  await deleteEndpoint(inst.id, id);
  return NextResponse.json({ id, deleted: true });
});
