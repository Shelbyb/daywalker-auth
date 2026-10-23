import { scimHandler, scimJson } from "@/lib/scim-http";
import { authenticateScim, resourceTypes } from "@/lib/auth/scim";

export const GET = scimHandler(async (req: Request, { params }: { params: Promise<{ connectionId: string }> }) => {
  const id = (await params).connectionId;
  await authenticateScim(req, id);
  return scimJson(resourceTypes(id));
});
