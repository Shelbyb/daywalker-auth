import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { requireSession } from "@/lib/auth/require-session";
import { verifyBody, runVerify } from "@/lib/auth/org-domains";

export const OPTIONS = preflight;

/** `{ method: "dns" }`, `{ method: "email", mailbox }` (sends a code) or `{ method: "email", code }` (confirms it). */
export const POST = handler(async (req: Request, { params }: { params: Promise<{ orgId: string; domainId: string }> }) => {
  const ctx = await frontendContext(req);
  const s = await requireSession(ctx.inst, ctx.refreshToken);
  const { orgId, domainId } = await params;
  const r = await runVerify(ctx.inst, orgId, s.userId, domainId, verifyBody.parse(await req.json()));
  return ctx.json("sentTo" in r ? r : { domain: r });
});
