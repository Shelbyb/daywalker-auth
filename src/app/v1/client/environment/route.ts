import { handler } from "@/lib/http";
import { frontendContext, preflight } from "@/lib/auth/frontend";
import { enabledProviders } from "@/lib/auth/oauth";
import { legalOf } from "@/lib/auth/legal";
import { emailCodeEnabled } from "@/lib/auth/email-sign-in";

export const OPTIONS = preflight;

/** Public instance settings the UI needs (which sign-in options to show). */
export const GET = handler(async (req: Request) => {
  const ctx = await frontendContext(req);
  return ctx.json({
    name: ctx.inst.name,
    oauthProviders: await enabledProviders(ctx.inst.id),
    passwordMinLength: ctx.inst.settings.passwordMinLength,
    legal: legalOf(ctx.inst),
    emailCodeSignIn: emailCodeEnabled(ctx.inst),
  });
});
