import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { renameSecurityKey } from "@/lib/auth/security-keys";

export const OPTIONS = preflight;

export const PATCH = handler(async (req: Request, { params }: { params: Promise<{ keyId: string }> }) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const { name } = z.object({ name: z.string().trim().min(1).max(60) }).parse(await req.json());
  await renameSecurityKey(s.userId, (await params).keyId, name);
  return ctx.json({ renamed: true });
});
