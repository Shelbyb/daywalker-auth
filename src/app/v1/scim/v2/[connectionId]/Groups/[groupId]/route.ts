import { scimHandler, scimJson, readScimBody } from "@/lib/scim-http";
import { authenticateScim } from "@/lib/auth/scim";
import { groupDelete, groupGet, groupPatch, groupReplace } from "@/lib/auth/scim-groups";

type Ctx = { params: Promise<{ connectionId: string; groupId: string }> };
const auth = async (req: Request, params: Ctx["params"]) => {
  const p = await params;
  return { c: await authenticateScim(req, p.connectionId), id: p.groupId };
};

export const GET = scimHandler(async (req: Request, { params }: Ctx) => {
  const { c, id } = await auth(req, params);
  return scimJson(await groupGet(c, id));
});

export const PUT = scimHandler(async (req: Request, { params }: Ctx) => {
  const { c, id } = await auth(req, params);
  return scimJson(await groupReplace(c, id, await readScimBody(req)));
});

export const PATCH = scimHandler(async (req: Request, { params }: Ctx) => {
  const { c, id } = await auth(req, params);
  return scimJson(await groupPatch(c, id, await readScimBody(req)));
});

export const DELETE = scimHandler(async (req: Request, { params }: Ctx) => {
  const { c, id } = await auth(req, params);
  await groupDelete(c, id);
  return new Response(null, { status: 204 });
});
