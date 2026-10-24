import { NextResponse } from "next/server";
import { z } from "zod";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { rotateSecret } from "@/lib/auth/m2m";

/** New secret (shown once). `graceMinutes` keeps the old one working for a while so deployments can switch over. */
export const POST = handler(async (req: Request, { params }: { params: Promise<{ clientId: string }> }) => {
  const inst = await instanceFromSecretKey(req);
  const { graceMinutes } = z.object({ graceMinutes: z.number().int().min(0).max(1440).default(0) }).strict().parse(await req.json().catch(() => ({})));
  return NextResponse.json(await rotateSecret(inst.id, (await params).clientId, graceMinutes, { type: "api" }));
});
