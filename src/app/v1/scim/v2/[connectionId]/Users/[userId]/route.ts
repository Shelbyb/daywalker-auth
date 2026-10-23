import { scimHandler, scimJson, readScimBody } from "@/lib/scim-http";
import { authenticateScim, scimDelete, scimGet, scimPatch, scimReplace } from "@/lib/auth/scim";

type Ctx = { params: Promise<{ connectionId: string; userId: string }> };
const auth = async (req: Request, params: Ctx["params"]) => {
  const p = await params;
  return { c: await authenticateScim(req, p.connectionId), id: p.userId };
};

export const GET = scimHandler(async (req: Request, { params }: Ctx) => {
  const { c, id } = await auth(req, params);
  return scimJson(await scimGet(c, id));
});

export const PUT = scimHandler(async (req: Request, { params }: Ctx) => {
  const { c, id } = await auth(req, params);
  return scimJson(await scimReplace(c, id, await readScimBody(req)));
});

export const PATCH = scimHandler(async (req: Request, { params }: Ctx) => {
  const { c, id } = await auth(req, params);
  return scimJson(await scimPatch(c, id, await readScimBody(req)));
});

export const DELETE = scimHandler(async (req: Request, { params }: Ctx) => {
  const { c, id } = await auth(req, params);
  await scimDelete(c, id);
  return new Response(null, { status: 204 });
});
