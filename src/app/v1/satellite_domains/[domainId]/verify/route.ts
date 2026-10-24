import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { verifySatellite } from "@/lib/auth/satellites";

/** Looks for the TXT record. 400 `verification_failed` until it is published. */
export const POST = handler(async (req: Request, { params }: { params: Promise<{ domainId: string }> }) =>
  NextResponse.json(await verifySatellite(await instanceFromSecretKey(req), (await params).domainId, { type: "api" })));
