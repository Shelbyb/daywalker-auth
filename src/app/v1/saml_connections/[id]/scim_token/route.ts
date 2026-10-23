import { NextResponse } from "next/server";
import { handler } from "@/lib/http";
import { instanceFromSecretKey } from "@/lib/auth/instance";
import { createScimToken, revokeScimToken } from "@/lib/auth/scim";
import { record } from "@/lib/audit";

type Ctx = { params: Promise<{ id: string }> };

/** Turn on SCIM provisioning for a connection, or rotate its token. The token is returned once. */
export const POST = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const { id } = await params;
  const r = await createScimToken(inst.id, id);
  void record(inst.id, "scim_token.created", { actor: { type: "api" }, target: id });
  return NextResponse.json(r, { status: 201, headers: { "cache-control": "no-store" } });
});

/** Turn SCIM provisioning off. */
export const DELETE = handler(async (req: Request, { params }: Ctx) => {
  const inst = await instanceFromSecretKey(req);
  const { id } = await params;
  await revokeScimToken(inst.id, id);
  void record(inst.id, "scim_token.revoked", { actor: { type: "api" }, target: id });
  return NextResponse.json({ id, scimEnabled: false });
});
