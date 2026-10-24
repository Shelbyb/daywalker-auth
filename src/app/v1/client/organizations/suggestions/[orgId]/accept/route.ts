import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { acceptSuggestion } from "@/lib/auth/org-domains";

export const OPTIONS = preflight;

export const POST = handler(async (req: Request, { params }: { params: Promise<{ orgId: string }> }) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  return ctx.json({ organization: await acceptSuggestion(ctx.inst, s.userId, (await params).orgId) });
});
