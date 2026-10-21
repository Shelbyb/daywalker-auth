import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { updateProfile, profileInput } from "@/lib/auth/account";
import { getUser } from "@/lib/auth/users";

export const OPTIONS = preflight;

/** Update the signed-in user's name. */
export const PATCH = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  await updateProfile(s.userId, profileInput.parse(await req.json()));
  return ctx.json({ user: await getUser(ctx.inst.id, s.userId) });
});
