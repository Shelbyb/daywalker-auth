import { NextResponse } from "next/server";
import { z } from "zod";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { listDeliveries } from "@/lib/webhooks";

/** Delivery log: status, attempts, next retry. Payloads and receiver responses are never returned. */
export const GET = handler(async (req: Request, { params }: { params: Promise<{ id: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  const { limit } = z.object({ limit: z.coerce.number().int().min(1).max(100).default(50) }).parse(Object.fromEntries(new URL(req.url).searchParams));
  return NextResponse.json({ data: await listDeliveries(inst.id, (await params).id, limit) });
});
