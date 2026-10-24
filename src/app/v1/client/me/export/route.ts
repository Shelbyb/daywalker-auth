import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { exportUserData, reauthInput } from "@/lib/auth/account-deletion";

export const OPTIONS = preflight;

/** The signed-in user's data as JSON, decrypted for them. POST (not GET) because it carries the re-authentication. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const input = reauthInput.parse(await req.json().catch(() => ({})));
  const data = await exportUserData(ctx.inst, s.userId, s.id, !!s.impersonatorId, input);
  const res = ctx.json(data);
  res.headers.set("Cache-Control", "no-store");
  res.headers.set("Content-Disposition", 'attachment; filename="my-data.json"');
  return res;
});
