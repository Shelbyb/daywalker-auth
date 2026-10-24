import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { deleteClient, getClient, updateClient } from "@/lib/auth/m2m";

type Ctx = { params: Promise<{ clientId: string }> };

export const GET = handler(async (req: Request, { params }: Ctx) => NextResponse.json(await getClient((await instanceFromSecretKey(req)).id, (await params).clientId)));

export const PATCH = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json(await updateClient(inst.id, (await params).clientId, await req.json(), { type: "api" }));
});

export const DELETE = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json(await deleteClient(inst.id, (await params).clientId, { type: "api" }));
});
