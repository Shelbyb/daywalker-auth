import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { safeRedirect } from "@/lib/auth/redirect";
import { sendInput, sendSignInEmail } from "@/lib/auth/email-sign-in";

export const OPTIONS = preflight;

/** Emails a sign-in code and link. Always answers "sent", so it can't reveal which emails have accounts. */
export const POST = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  const input = sendInput.parse(await req.json());
  await ctx.limit("esi_send", 10, 900);
  await sendSignInEmail(ctx.inst, input.email, safeRedirect(input.redirectUrl, ctx.inst.allowedOrigins));
  return ctx.json({ status: "sent" });
});
