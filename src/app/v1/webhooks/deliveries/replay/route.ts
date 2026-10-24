import { NextResponse } from "next/server";
import { z } from "zod";
import { handler, errors } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { rateLimit } from "@/lib/cache";
import { replayFailed } from "@/lib/webhooks";

const Body = z.object({
  from: z.string().max(40).pipe(z.coerce.date()),
  to: z.string().max(40).pipe(z.coerce.date()),
  endpointId: z.string().max(200).optional(),
});

/** Replay every failed delivery created between `from` and `to` (max 500 per call, max 30 days). */
export const POST = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  if ((await rateLimit(`${inst.id}:webhook_bulk_replay`, 10, 3600)) < 0) throw errors.tooMany();
  const input = Body.parse(await req.json().catch(() => ({})));
  return NextResponse.json(await replayFailed(inst.id, input), { status: 202 });
});
