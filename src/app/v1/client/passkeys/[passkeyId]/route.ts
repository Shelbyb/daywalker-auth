import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { renamePasskey, deletePasskey } from "@/lib/auth/passkeys";

export const OPTIONS = preflight;
type Ctx = { params: Promise<{ passkeyId: string }> };

/** Rename one of your passkeys. */
export const PATCH = handler(async (req: Request, { params }: Ctx) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const { name } = z.object({ name: z.string().max(60) }).parse(await req.json());
  await renamePasskey(s.userId, (await params).passkeyId, name);
  return ctx.json({ ok: true });
});

/** Remove one of your passkeys. Other users' passkey IDs 404. */
export const DELETE = handler(async (req: Request, { params }: Ctx) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await deletePasskey(s.userId, (await params).passkeyId);
  return ctx.json({ deleted: true });
});
