import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { getByBackend, revokeByBackend } from "@/lib/auth/api-keys";

type Ctx = { params: Promise<{ keyId: string }> };
export const GET = handler(async (req: Request, { params }: Ctx) => NextResponse.json(await getByBackend(await instanceFromSecretKey(req), (await params).keyId)));
/** Revokes the key (it stays listed with `revokedAt`). */
export const DELETE = handler(async (req: Request, { params }: Ctx) => NextResponse.json(await revokeByBackend(await instanceFromSecretKey(req), (await params).keyId, { type: "api" })));
