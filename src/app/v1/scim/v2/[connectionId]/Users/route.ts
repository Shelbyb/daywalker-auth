import { scimHandler, scimJson, readScimBody } from "@/lib/scim-http";
import { authenticateScim, scimCreate, scimList } from "@/lib/auth/scim";

type Ctx = { params: Promise<{ connectionId: string }> };

export const GET = scimHandler(async (req: Request, { params }: Ctx) => {
  const c = await authenticateScim(req, (await params).connectionId);
  const q = new URL(req.url).searchParams;
  const num = (k: string) => (q.has(k) && /^\d{1,6}$/.test(q.get(k)!) ? Number(q.get(k)) : undefined);
  return scimJson(await scimList(c, { filter: q.get("filter")?.slice(0, 500), startIndex: num("startIndex"), count: num("count") }));
});

export const POST = scimHandler(async (req: Request, { params }: Ctx) => {
  const c = await authenticateScim(req, (await params).connectionId);
  return scimJson(await scimCreate(c, await readScimBody(req)), 201);
});
