import { NextResponse } from "next/server";
import { z } from "zod";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { createEndpoint, listEndpoints } from "@/lib/webhooks";

export const GET = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json({ data: await listEndpoints(inst.id) });
});

/** Register an endpoint. The response includes the signing secret; it is shown only now (and on rotation). */
export const POST = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const body = z
    .object({ url: z.string().max(2000), events: z.array(z.string().max(64)).max(20).optional(), description: z.string().max(200).nullish() })
    .parse(await req.json());
  return NextResponse.json(await createEndpoint(inst.id, body), { status: 201 });
});
