import { z } from "zod";
import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { connectionForEmail } from "@/lib/auth/saml";

export const OPTIONS = preflight;

/** Does this email's domain use single sign-on? Lets a sign-in form offer "Continue with SSO". */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  await ctx.limit("sso_check", 60, 300);
  const { email } = z.object({ email: z.string().trim().toLowerCase().email().max(254) }).parse(await req.json());
  const c = await connectionForEmail(ctx.inst.id, email);
  return ctx.json({ sso: !!c, connectionName: c?.name ?? null, required: !!c?.ssoRequired });
});
