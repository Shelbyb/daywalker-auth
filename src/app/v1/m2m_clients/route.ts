import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { createClient, listClients } from "@/lib/auth/m2m";

/** Backend API: machine-to-machine clients (client credentials). */
export const GET = handler(async (req: Request) => NextResponse.json({ data: await listClients((await instanceFromSecretKey(req)).id) }));

/** Returns `clientSecret` once. */
export const POST = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json(await createClient(inst.id, await req.json(), { type: "api" }), { status: 201 });
});
