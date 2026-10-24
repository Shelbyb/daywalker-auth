import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { removeSatellite } from "@/lib/auth/satellites";

export const DELETE = handler(async (req: Request, { params }: { params: Promise<{ domainId: string }> }) =>
  NextResponse.json(await removeSatellite(await instanceFromSecretKey(req), (await params).domainId, { type: "api" })));
