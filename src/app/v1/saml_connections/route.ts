import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { createConnection, listConnections } from "@/lib/auth/saml";
import { record } from "@/lib/audit";

export const GET = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  return NextResponse.json({ data: await listConnections(inst.id) });
});

/** Create an SSO connection from fields, or from `metadataXml` plus `name` and `domains`. */
export const POST = handler(async (req: Request) => {
  const inst = await instanceFromSecretKey(req);
  const c = await createConnection(inst.id, await req.json());
  void record(inst.id, "sso_connection.created", { actor: { type: "api" }, target: c.id, data: { name: c.name, domains: c.domains } });
  return NextResponse.json(c, { status: 201 });
});
